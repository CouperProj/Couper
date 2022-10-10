#ifndef _UTILITY_H_
#define _UTILITY_H_

#include<iostream>
#include<sstream>
#include<fstream>
#include<bitset>
#include<string>
#include<unordered_map>
#include<vector>
#include<cmath>
#include"mylibpcap.h"

using namespace std;

struct IdSpread{
public:
    string flowID;
    uint32_t spread;   // spread means cardinality
    IdSpread(){}
    IdSpread(string str, uint32_t s){flowID = str; spread = s;}
};

bool IdSpreadComp(IdSpread& a, IdSpread& b){
    return a.spread > b.spread;
}

inline uint32_t get_one_num(uint8_t val){
    bitset<8> tmp(val);
    return tmp.count();
}


/* A min-heap is used to record super spreaeder candidates for piggyback strategy in bSkt, rerSkt and VHS*/
struct MinHeapCmp {
    inline bool operator()(const IdSpread &x, const IdSpread &y){
        return x.spread > y.spread;
    }
};

string Uint32toIPstr(uint32_t val){
    string ret = "";
    for(size_t i = 0;i < 4;i++){
        uint8_t tmpval = (val >> (i * 8)) & 255;
        string tmpstr = to_string(tmpval);
        ret = (string(3 - tmpstr.length(), '0') + tmpstr) + ret;
    }
    return ret;
}

uint32_t IPstrtoUint32(string IPstr){
    uint32_t ret = 0;
    for(size_t i = 0;i < 4;i++){
        uint32_t tmp = stoi(IPstr.substr(i*3,3));
        ret = (ret << 8) + tmp;
    }
    return ret;
}

uint32_t get_leading_zeros(uint32_t bitstr){
    uint32_t tmp = 2147483648;   //1<<31
    for(size_t i = 0;i < 32;i++){
        if((bitstr & tmp) != 0)
            return i;
        tmp >>= 1;
    }
    return 32;
}

class TXT_Handler{
private:
    ifstream txtfile;
    bool eof_flag = false;
    uint32_t pkt_num = 0;
public:
    TXT_Handler(string data_path, string filename);
    int get_packet(string& flowID, string& elemID);
};

TXT_Handler::TXT_Handler(string data_path, string filename){
    string txtfile_name = data_path + "/" + filename;
    txtfile.open(txtfile_name);
}

int TXT_Handler::get_packet(string& flowID, string& elemID){
    string linedata;
    getline(txtfile, linedata);
    if(txtfile.eof() || linedata==""){
        printf("TXT file parse over !\n");
        eof_flag = true;  
        cout<<" pkt num:"<<pkt_num<<endl;
        txtfile.close();
        return 0;
    }
    pkt_num++;
    flowID = linedata.substr(0, linedata.find(' '));
    elemID = linedata.substr(linedata.find(' ')+1);
    return 1;
}

class FILE_HANDLER{
private:
    string data_path = "../../data_sets";
    PCAP_SESSION* pcap_handler;
    TXT_Handler* txt_handler;
    string dataset;
    string filename;
    uint32_t item_num = 0;
    uint32_t file_type = 0;
#define PCAP_FILE 1
#define TXT_FILE 2
public:
    FILE_HANDLER(string filename);
    int get_item(string& flowID, string& elemID);
    uint32_t proc_num();
    string get_filename();
};

FILE_HANDLER::FILE_HANDLER(string filename){
    if (filename.find("pcap") != string::npos) {
        cout << "pcap file....." << endl;
        pcap_handler = new PCAP_SESSION(data_path, filename);
        file_type = PCAP_FILE;
    }
    else if (filename.find("txt") != string::npos) {
        txt_handler = new TXT_Handler(data_path, filename);
        file_type = TXT_FILE;
    } else {
        cout << "unsupported file type....." << endl;
    }
    cout << this->get_filename() << endl;
}

int FILE_HANDLER::get_item(string& flowID, string& elemID){
    int status;
    if (file_type = PCAP_FILE) {
        IP_PACKET cur_packet;
        status = pcap_handler->get_packet(cur_packet);
        flowID = cur_packet.get_srcip();
        elemID = cur_packet.get_dstip();
    } else {
        status = txt_handler->get_packet(flowID, elemID);
    }
    if (status != 0)
        item_num++;
    return status;
}

uint32_t FILE_HANDLER::proc_num(){
    return item_num;
}

string FILE_HANDLER::get_filename(){
    return filename;
}

void write_superspreaders(string ofile_path, vector<IdSpread>& superspreaders){
    ofstream ofile_hand;
    string ofile_name = ofile_path + "/SuperSpreaders.txt";
    ofile_hand = ofstream(ofile_name);
    if(!ofile_hand){
        cout<<"fail to open files."<<endl;
        return;
    }
    bool first_line = true;
    for(auto item : superspreaders){
        if(first_line)
            first_line = false;
        else
            ofile_hand << endl;
        ofile_hand << item.flowID << " " << item.spread;
    }
    ofile_hand.close();
}

#endif