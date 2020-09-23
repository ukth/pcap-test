#include <pcap.h>
#include <stdio.h>
#include <libnet.h>

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}


void print_eth(struct libnet_ethernet_hdr eth_hdr){
	printf("src MAC add: ");
	for(int i = 5; i > 0; i--){
		printf("%x:",eth_hdr.ether_shost[i]);
	}
	printf("%x\n",eth_hdr.ether_shost[0]);

	printf("dst MAC add: ");
	for(int i = 5; i > 0; i--){
		printf("%x:",eth_hdr.ether_dhost[i]);
	}
	printf("%x\n\n",eth_hdr.ether_dhost[0]);

}

void print_ipv4(struct libnet_ipv4_hdr ipv4_hdr){

	printf("ipv4 src add: %s\n",inet_ntoa(ipv4_hdr.ip_src));

	printf("ipv4 dst add: %s\n\n",inet_ntoa(ipv4_hdr.ip_dst));

}

void print_tcp(struct libnet_tcp_hdr tcp_hdr, u_char* payload){

	printf("tcp src port: %d\n", ntohs(tcp_hdr.th_sport));
	printf("tcp dst port: %d\n\n", ntohs(tcp_hdr.th_dport));

	printf("data:\n");


	for(int i =0; i < 16; i++){
		printf("%02x ", *(payload+i));
	}

	printf("\n\n########################################\n\n");

}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        
        struct libnet_ethernet_hdr eth_hdr;
        struct libnet_ipv4_hdr ipv4_hdr;
        struct libnet_tcp_hdr tcp_hdr;

        const u_char* packet;
        u_char* p;

        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        printf("%u bytes captured\n", header->caplen);

        p = (u_char*)packet;
        memcpy(&eth_hdr, p, 14);
        p += 14;
        memcpy(&ipv4_hdr, p, 20);
        p += 20;
        memcpy(&tcp_hdr, p, 20);
        p += tcp_hdr.th_off * 4;

        print_eth(eth_hdr);
        print_ipv4(ipv4_hdr);
        print_tcp(tcp_hdr, p);




    }
    pcap_close(handle);

}
