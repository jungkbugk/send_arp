#pragma once


#include <pcap.h>

#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <errno.h>

#define PACKET_SIZE 42
#define ETH_LENGTH 14
#define ARPTYPE 0x0806
#define IP_SIZE 4
#define MAC_SIZE 6
#define ARP_ETHERNET 1
#define IPv4 0x0800
#define ARP_HWSIZE 6
#define ARP_PROTOCOLSIZE 4
#define ARP_REQ 1
#define ARP_REP 2



struct ethernet_header{
   uint8_t dst_mac[6];
   uint8_t src_mac[6];
   uint16_t type;
};

struct arp_header{
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_size;
    uint8_t protocol_size;
    uint16_t opcode;
    uint8_t sender_mac[6];
    uint32_t sender_ip;
    uint8_t target_mac[6];
    uint32_t target_ip;
}__attribute__((packed));

void get_mac(uint8_t MAC[6], char *interface);
int send_arp(char *interface, char *target_ip, char *sender_ip);
int check_arp_reply(const unsigned char *packet, uint8_t eth_dst_mac[6], uint8_t eth_my_mac[6], char *sender_ip);
char *get_host_ip(char *interface);

