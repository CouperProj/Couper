#ifndef _BSKT_H_
#define _BSKT_H_

#include<iostream>
#include<array>
#include<string>
#include<math.h>
#include<vector>
#include<algorithm>
#include<set>
#include "hashfunc.h"
#include "util.h"
using namespace std;

#define HASH_SEED_1 92317
#define HASH_SEED_2 37361 
#define HASH_SEED_3 52813

class HLL{
public:
    static const uint32_t register_num = 128;
    static const uint32_t register_size = 5;
    static const uint32_t size = register_num * register_size;
    static const uint32_t HLL_size = register_num * register_size;
    static constexpr double alpha_m = 0.7213/(1+1.079/128); 
    array<uint8_t,register_num> HLL_registers{};
    uint8_t get_leading_zeros(uint32_t bitstr);
    void record_element(uint32_t hashres);
    int get_spread();
};

class Bitmap{
public:
    static const uint32_t bitnum = 5000;
    static const uint32_t size = bitnum;
    array<uint8_t,bitnum/8> raw{};
    void record_element(uint32_t hashres);
    uint32_t get_unitval(uint32_t bitpos);
    int get_spread();
    void reset();
    Bitmap(){ reset(); }
};


template<class Estimator>
class bSkt{
public:
    uint32_t memory;  //kB
    uint32_t table_size = memory * 1024 * 8 / 4 /Estimator::size;
    vector<vector<Estimator>> tables;
    void process_packet(string flowid,string element);
    void report_superspreaders(vector<IdSpread>& superspreaders);
    bSkt(uint32_t memory_);
    uint32_t get_flow_cardinality(string flowid);

    bool DETECT_SUPERSPREADER = false;   //detect super spreaders with piggyback
    uint32_t heap_size = 400;
    set<string> inserted;
    vector<IdSpread> heap;
};

template<class Estimator>
bSkt<Estimator>::bSkt(uint32_t memory_):memory(memory_), table_size(memory * 1024 * 8 / 4 /Estimator::size), tables(4){
    tables[0].resize(table_size);
    tables[1].resize(table_size);
    tables[2].resize(table_size);
    tables[3].resize(table_size);
}

template<class Estimator>
void bSkt<Estimator>::report_superspreaders(vector<IdSpread>& superspreaders){
    superspreaders.clear();
    for(size_t i = 0;i < heap.size();i++){
        superspreaders.push_back(IdSpread(heap[i].flowID, heap[i].spread));
    }
    sort(superspreaders.begin(), superspreaders.end(), IdSpreadComp);
}

#endif