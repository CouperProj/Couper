#ifndef _RERSKT_H_
#define _RERSKT_H_

#include<iostream>
#include<array>
#include<string>
#include<math.h>
#include<vector>
#include<algorithm>
#include<set>
#include"util.h"
#include"hashfunc.h"
using namespace std;

#define HASH_SEED_1 92317
#define HASH_SEED_2 37361 
// #define HASH_SEED_3 52813

class HLL{
public:
    static const uint32_t register_num = 128;
    static const uint32_t register_size = 5;
    static const uint32_t size = register_num * register_size;
    static const uint32_t HLL_size = register_num * register_size;
    static constexpr double alpha_m = 0.7213/(1+1.079/128); 
    array<uint8_t,register_num> HLL_registers{};

public:
    uint8_t get_leading_zeros(uint32_t bitstr);
    void record_element(uint32_t hash_elem, uint32_t unit_pos);
    static int get_spread(array<uint8_t,register_num> virtual_HLL);
    int get_spread();
    void set_unit(uint32_t pos,uint32_t val);
    void reset();
    uint32_t get_unitval(uint32_t pos){ return HLL_registers[pos]; }
    uint32_t get_unit_num(){ return register_num; }
    HLL(){ reset(); }
};

class Bitmap{
public:
    static const uint32_t bitnum = 5000;
    static const uint32_t size = bitnum;
    array<uint8_t,bitnum/8> raw{};

public:
    Bitmap(){ reset(); }
    uint32_t get_unit_num(){ return bitnum; }
    void record_element(uint32_t hash_elem, uint32_t unit_pos);
    uint32_t get_unitval(uint32_t bitpos);
    int get_spread();
    void set_unit(uint32_t pos,uint32_t val);
    void reset();
};


template<class Estimator>
class RerSkt{
private:
    uint32_t memory;  //kB
    uint32_t table_size;
    vector<Estimator> table1;
    vector<Estimator> table2;
    
    bool DETECT_SUPERSPREADER = false;    //detect super spreaders with piggyback
    uint32_t heap_size = 300;
    vector<IdSpread> heap;
    set<string> inserted;

public:
    void process_packet(string flowid, string element);
    int get_flow_cardinality(string flowid);
    RerSkt(uint32_t memory_);
};


#endif