#include <cstdio>
#include <pcap.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include "ethhdr.h"
#include "arphdr.h"

#define MAC_ALEN 6

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp-test <interface> <sender_IP1> <target_IP1> [<sender_IP2> <target_IP2> ...]\n");
    printf("sample: send-arp-test wlan0 192.168.1.1 192.168.1.2 192.168.1.3 192.168.1.4\n");
}

void GetInterfaceMacAddress(char* interface, unsigned char* mac) {
    int fd;
    struct ifreq ifr;
    fd = socket(AF_INET, SOCK_DGRAM, 0);

    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        printf("ioctl error\n");
        close(fd);
        return;
    }

    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

    close(fd);
}

void send_arp_packet(pcap_t* handle, char* dev, char* sender_IP, char* target_IP) {
    int ret; // Return value
    unsigned char my_mac[6];

    GetInterfaceMacAddress(dev, my_mac);

    EthArpPacket arp_req_packet;
    arp_req_packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    arp_req_packet.eth_.smac_ = Mac(my_mac);
    arp_req_packet.eth_.type_ = htons(EthHdr::Arp);

    arp_req_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    arp_req_packet.arp_.pro_ = htons(EthHdr::Ip4);
    arp_req_packet.arp_.hln_ = sizeof(Mac);
    arp_req_packet.arp_.pln_ = sizeof(Ip);
    arp_req_packet.arp_.op_ = htons(ArpHdr::Request);
    arp_req_packet.arp_.smac_ = Mac(my_mac);
    arp_req_packet.arp_.sip_ = inet_addr(target_IP);
    arp_req_packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    arp_req_packet.arp_.tip_ = inet_addr(sender_IP);

    
    ret = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&arp_req_packet), sizeof(EthArpPacket));
    if (ret != 0) {
        printf("[%s] Error sending the packet: %s\n", dev, pcap_geterr(handle));
        return;
    }
    printf("ARP Request sent: Source IP: %s, Target IP: %s\n", target_IP, sender_IP);
}

int main(int argc, char* argv[]) {
    if (argc < 4 || argc % 2 != 0) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    for (int i = 2; i < argc; i += 2) {
        send_arp_packet(handle, dev, argv[i], argv[i + 1]);
    }

    pcap_close(handle);
    return 0;
}
