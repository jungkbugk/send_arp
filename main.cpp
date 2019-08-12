#include <pcap.h>
#include <stdio.h>
#include <cstdint>
#include "send_arp.h"

void usage() {
  printf("syntax: send_arp <interface> <sender ip> <target ip>\n");
  printf("sample: send_arp wlan0 8.8.8.8 192.168.3.1\n");
}


int main(int argc, char *argv[])
{
    //QCoreApplication a(argc, argv);
    //타겟 IP
    if(argc!=2){
        usage();//사용방법 출력
        return -1;
    }
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
      fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
      return -1;
    }



    printf("sss");
    return 0;
}
