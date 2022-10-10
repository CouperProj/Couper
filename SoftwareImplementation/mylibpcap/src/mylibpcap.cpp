#include "mylibpcap.h"
#include<cstring>
#include<sstream>

void IP_PACKET::setsrc(uint32_t val) {
    this->srcdot[0] = val;
    this->srcdot[1] = val>>8;
    this->srcdot[2] = val>>16;
    this->srcdot[3] = val>>24;
}

void IP_PACKET::setdst(uint32_t val) {
    this->dstdot[0] = val;
    this->dstdot[1] = val>>8;
    this->dstdot[2] = val>>16;
    this->dstdot[3] = val>>24;
}

void IP_PACKET::setsrc(string str) {
    istringstream readstr(str);
    string tmp;
    for(size_t i = 0;i < 4;i++) {
        getline(readstr,tmp,'.');
        this->srcdot[i] = stoi(tmp);
    }
}

void IP_PACKET::setdst(string str) {
    istringstream readstr(str);
    string tmp;
    for(size_t i = 0;i < 4;i++) {
        getline(readstr,tmp,'.');
        this->dstdot[i] = stoi(tmp);
    }
}

void IP_PACKET::show_ip() {
    cout<<"src ip: "<<unsigned(srcdot[0]) <<"."<<unsigned(srcdot[1]) <<"."<<
    unsigned(srcdot[2]) <<"."<<unsigned(srcdot[3])
    <<"  dst ip: "<<unsigned(dstdot[0]) <<"."<<unsigned(dstdot[1]) <<"."<<
    unsigned(dstdot[2]) <<"."<<unsigned(dstdot[3]) <<endl;
}

string IP_PACKET::get_ipstr() {
    string ret = "";
    string tmp;
    for(int i=0;i<4;i++) {
        tmp = to_string(srcdot[i]);
        ret += (string(3 - tmp.length(), '0') + tmp);
    }
    for(int i=0;i<4;i++) {
        tmp = to_string(dstdot[i]);
        ret += (string(3 - tmp.length(), '0') + tmp);
    }
    return ret;
}

string IP_PACKET::get_srcip() {
    string ret = "";
    string tmp;
    for(int i=0;i<4;i++) {
        tmp = to_string(srcdot[i]);
        ret += (string(3 - tmp.length(), '0') + tmp);
    }
    return ret;
}

string IP_PACKET::get_dstip() {
    string ret = "";
    string tmp;
    for(int i=0;i<4;i++) {
        tmp = to_string(dstdot[i]);
        ret += (string(3 - tmp.length(), '0') + tmp);
    }
    return ret;
}

int PCAP_SESSION::get_packet(IP_PACKET& ret_pk) {
    const u_char *pktStr;// = pcap_next(pcap_session, &pkthdr);
    int status = pcap_next_ex(pcap_session,&pkthdr,&pktStr);
// cout<<"status: "<<status<<endl;
#ifdef DUBUG_PARSE
    for (u_int i=0; (i < pkthdr->caplen ) ; i++)
    {
        // Start printing on the next after every 16 octets
        if ( (i % 16) == 0) printf("\n");

        // Print each octet as hex (x), make sure there is always two characters (.2).
        printf("%u ", pktStr[i]);
    }
    cout<<endl;
#endif
    if (status < 1){
            printf("Pcap file parse over !\n");
            eof_flag = true;
            pcap_close(pcap_session);
            cout<<"status: "<<status<<" pkt num:"<<pkt_num<<endl;
            return 0;
        }
    ip_pkt = (struct my_ip*)(pktStr + SIZE_ETHERNET);
    pkt_num++;
    ret_pk.setsrc(ip_pkt->ip_src.s_addr);
    ret_pk.setdst(ip_pkt->ip_dst.s_addr);
    
    return 1;
}