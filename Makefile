CXX = g++
CXXFLAGS = -g -Wall -std=c++11
LIBS = -lpcap
INCLUDES = -I.

OBJS = main.o arphdr.o ethhdr.o ip.o mac.o
TARGET = arp-spoof

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS) $(LIBS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c -o $@ $<

clean:
	rm -f $(TARGET) $(OBJS)

.PHONY: all clean

