#ifndef _MY_LIB_PCAP_
#define _MY_LIB_PCAP_

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <iostream>
#include <string>
#include <fstream>
using namespace std;

struct my_ip{
	u_int8_t	ip_vhl;		/* header length, version */
#define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)	((ip)->ip_vhl & 0x0f)
	u_int8_t	ip_tos;		/* type of service */
	u_int16_t	ip_len;		/* total length */
	u_int16_t	ip_id;		/* identification */
	u_int16_t	ip_off;		/* fragment offset field */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
	u_int8_t	ip_ttl;		/* time to live */
	u_int8_t	ip_p;		/* protocol */
	u_int16_t	ip_sum;		/* checksum */
	struct	in_addr ip_src,ip_dst;	/* source and dest address */
};

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

	/* Ethernet header */
	struct sniff_ethernet {
		u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
		u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
		u_short ether_type; /* IP? ARP? RARP? etc */
	};

	/* IP header */
	struct sniff_ip {
		u_char ip_vhl;		/* version << 4 | header length >> 2 */
		u_char ip_tos;		/* type of service */
		u_short ip_len;		/* total length */
		u_short ip_id;		/* identification */
		u_short ip_off;		/* fragment offset field */
	#define IP_RF 0x8000		/* reserved fragment flag */
	#define IP_DF 0x4000		/* don't fragment flag */
	#define IP_MF 0x2000		/* more fragments flag */
	#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
		u_char ip_ttl;		/* time to live */
		u_char ip_p;		/* protocol */
		u_short ip_sum;		/* checksum */
		struct in_addr ip_src,ip_dst; /* source and dest address */
	};
	// #define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
	// #define IP_V(ip)		(((ip)->ip_vhl) >> 4)

	/* TCP header */
	typedef u_int tcp_seq;

	struct sniff_tcp {
		u_short th_sport;	/* source port */
		u_short th_dport;	/* destination port */
		tcp_seq th_seq;		/* sequence number */
		tcp_seq th_ack;		/* acknowledgement number */
		u_char th_offx2;	/* data offset, rsvd */
	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
		u_char th_flags;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
		u_short th_win;		/* window */
		u_short th_sum;		/* checksum */
		u_short th_urp;		/* urgent pointer */
    };

#define SIZE_ETHERNET 14

class IP_PACKET{

public:
    uint8_t srcdot[4];
    uint8_t dstdot[4];
    uint32_t src;
    uint32_t dst;
    void setsrc(uint32_t val);
    void setdst(uint32_t val);
	void setsrc(string str);
    void setdst(string str);
	void show_ip();
	string get_ipstr();
	string get_srcip();
	string get_dstip();
   // IP_PACKET();
};

class PCAP_SESSION{

private:
	int file_type;

    //variables for pcap session
    char ebuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap_session;
    struct pcap_pkthdr* pkthdr;
    //struct sniff_ip* ip_pkt;  
    struct my_ip* ip_pkt;

	//variables for csv session
	ifstream csv_file;

    uint32_t pkt_num = 0;
    bool eof_flag = false;

public:
	PCAP_SESSION(string data_path, string filename){
		string pcap_file = data_path + "/" + filename;
		pcap_session = pcap_open_offline(pcap_file.c_str(), ebuf);
	}
    int get_packet(IP_PACKET& ret_pkt);
    bool eof(){return eof_flag;}
	uint32_t proc_num(){return pkt_num;}
};


#endif