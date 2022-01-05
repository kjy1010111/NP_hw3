#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <pcap.h>
#include <string.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

int main(int argc , char **argv){
	int res , packet_no = 1;
	char *file;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handler;
	struct pcap_pkthdr *header;
	struct ether_header *ether_h;
	u_char *packet;

	if(argc < 2){
		printf("no file\n");
		return 0;
	}
	else{
		file = strdup(argv[1]);
	}

	handler = pcap_open_offline(file , errbuf);

	while((res = pcap_next_ex(handler , &header , (const u_char **)&packet)) >= 0){
		if(res == 0) continue;

		ether_h = (struct ether_header *)packet;

		printf("Pakcet No: %d\n" , packet_no++);
		printf("Time: %s" , ctime((const time_t *)&header->ts.tv_sec));
		printf("Packet Length: %d\n" , header->len);
		printf("Source MAC Address: %s\n" , ether_ntoa((struct ether_addr *)&ether_h->ether_shost));
		printf("Destination MAC Address: %s\n" , ether_ntoa((struct ether_addr *)&ether_h->ether_dhost));
		if(ntohs(ether_h->ether_type) == ETHERTYPE_IP){
			printf("Ether Type: IP\n");

			struct ip *ip;
			u_int ip_size;
			ip = (struct ip*)(packet + sizeof(struct ether_header));
			ip_size = ip->ip_hl * 4;

			printf("Source IP Address: %s\n" , inet_ntoa(ip->ip_src));
			printf("Destination IP Address: %s\n" , inet_ntoa(ip->ip_dst));

			if(ip->ip_p == IPPROTO_TCP){
				struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_size);
				printf("Source IP port: %d\n" , tcp->th_sport);
				printf("Destination IP port: %d\n" , tcp->th_dport);
			}
			else if(ip->ip_p == IPPROTO_UDP){
				struct udphdr *udp = (struct udphdr *)(packet + sizeof(struct ether_header) + ip_size);
				printf("Source IP port: %d\n" , udp->uh_sport);
				printf("Destination IP port: %d\n" , udp->uh_dport);
			}
		}
		else if(ntohs(ether_h->ether_type) == ETHERTYPE_PUP){
			printf("Ether Type: Xerox PUP\n");
		}
		else if(ntohs(ether_h->ether_type) == ETHERTYPE_SPRITE){
			printf("Ether Type: Sprite\n");
		}
		else if(ntohs(ether_h->ether_type) == ETHERTYPE_ARP){
			printf("Ether Type: Address resolution\n");
		}
		else if(ntohs(ether_h->ether_type) == ETHERTYPE_REVARP){
			printf("Ether Type: Reverse ARP\n");
		}
		else if(ntohs(ether_h->ether_type) == ETHERTYPE_AT){
			printf("Ether Type: AppleTalk protocol\n");
		}
		else if(ntohs(ether_h->ether_type) == ETHERTYPE_AARP){
			printf("Ether Type: AppleTalk ARP\n");
		}
		else if(ntohs(ether_h->ether_type) == ETHERTYPE_VLAN){
			printf("Ether Type: IEEE 802.1Q VLAN tagging\n");
		}
		else if(ntohs(ether_h->ether_type) == ETHERTYPE_IPX){
			printf("Ether Type: IPX\n");
		}
		else if(ntohs(ether_h->ether_type) == ETHERTYPE_IPV6){
			printf("Ether Type: IP protocol version 6\n");
		}
		else{
			printf("Ether Type: unknown\n");
		}

		printf("\n=======================================\n\n");
	}
}
