#include <pcap.h>
#include <stdio.h>
#include <stdint.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

//void print_mac()

/* -ETH 다음에 IP가 오는지 확인하는 코드가 들어갈 것(정확한 작동 방식은 구글링해서 익힐 것).

   -IP 다음에 TCP가 오는지 확인하는 코드가 들어갈 것(정확한 작동 방식은 구글링해서 익힐 것).

   -TCP Data의 위치와 크기를 알아내는 코드가 들어갈 것(정확한 작동 방식은 구글링해서 익힐 것).

   -TCP Data는 최대 10바이트까지만 찍을 것(최대라고 했지 무조건 10은 아님. 10보다 데이터의 크기가 작을 수도 있음).

   -mac, ip, port를 출력할 때 코드의 중복이 없도록 별도의 함수를 만들어 사용할 것(일요일 실습 내용 참고). */


struct N {
    int i, k;
    const u_char* mac;
    const u_char* ip;
    const u_char* port;
    const u_char* data_location;
    const u_char* tcp_data;
    const u_char* sth;

    const uint16_t* m1;
    const uint16_t* m2;
    const uint8_t* n;
    const uint8_t* l;
    const u_char* o1;
    const u_char* o2;
    const uint8_t* p;
    const uint8_t* q;

    uint8_t tcp_serial(const u_char* sth) {
        if (sth[0] == NULL) {return k = -1;}
        else {return k = 1;}
    ;}

    void print_1(const u_char* mac) { printf("%02X:%02X:%02X:%02X:%02X:%02X\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]); }
    void print_2(const u_char* ip) { printf("%u.%u.%u.%u\n", ip[0], ip[1], ip[2], ip[3]); }
    void print_3(const u_char* port) { printf("%d\n", (port[0] << 8) | port[1]) ; }
    void print_4(const u_char* data_location) {
        if (k == 1) {
            printf("%02X\n", data_location[0]);
        } else {
            printf("\n");
        }
    ;}
    void print_5(const u_char* tcp_data) {
        if (k == 1) {
            for (i=0; i<10; i++) {
                printf("%d ", tcp_data[i]);}}

    ;}

    uint16_t total_len(const u_char* m1, const u_char* m2) {
        return ((m1[0] & 0xFF00 >> 8) | (m2[0] & 0x00FF << 8)); // | (m2[0] & 0x0000FF00 << 8) | (m2[0] & 0x000000FF) << 24);
    }
    uint8_t ip_hdr_len(const uint8_t* n) {
        return (n[0] << 4 | n[1]);
    }
    uint8_t tcp_hdr_len(const uint8_t* l) {
        return (l[0] >> 4);
    }
    void print_tcp_data_len(const u_char* o1, const u_char* o2, const uint8_t* p, const uint8_t* q) {
        uint16_t r;
        r = total_len(o1, o2) - (ip_hdr_len(p) + tcp_hdr_len(q))*4;
        printf("%d\n", r);
    }

};




int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;


  }
int len=0;
  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("\n%u bytes captured\n", header->caplen);
    printf("%02x %02x %02x\n ", packet[0], packet[1], packet[2]);

    N p;
    printf("====================================================================\n");
    p.tcp_serial(&packet[54]);
    printf("Dmac : ");
    p.print_1(&packet[0]);
    printf("Smac : ");
    p.print_1(&packet[6]);
    printf("Sip : ");
    p.print_2(&packet[26]);
    printf("Dip : ");
    p.print_2(&packet[30]);
    printf("Sport : ");
    p.print_3(&packet[34]);
    printf("Dport : ");
    p.print_3(&packet[36]);
    printf("TCP data locaion : ");
    p.print_4(&packet[54]);
    printf("TCP data length : ");
    p.print_tcp_data_len(&packet[16], &packet[17], &packet[14], &packet[46]);
    printf("TCP Data : ");
    p.print_5(&packet[54]);




  }


  pcap_close(handle);
  return 0;
}
