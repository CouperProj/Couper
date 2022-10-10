#ifndef _V_HLL_
#define _V_HLL_

#include<vector>
#include<iostream>
#include<array>
#include<algorithm>
#include"hashfunc.h"
#include"util.h"
#include<set>
using namespace std;

#define HASH_SEED_1 92317
#define HASH_SEED_2 37361

class VHS{
public:
    uint32_t memory;
    static const uint32_t HLL_size = 128;
    static const uint32_t glb_HLL_size = 1024;
    static const uint32_t register_size = 5;
    uint32_t register_num;
    vector<uint32_t> raw;
    vector<uint8_t> global_HLL;
  
    VHS(uint32_t mem);
    void process_packet(string flowID, string elementID);
    uint8_t get_register(uint32_t reg_pos);
    void set_register(uint32_t reg_pos, uint8_t val);
    uint32_t get_spread(vector<uint8_t> virtual_HLL);
    int get_flow_cardinality(string flowID);

    bool DETECT_SUPERSPREADER = false;    //detect superspreaders
    static const uint32_t heap_size = 300;
    vector<IdSpread> heap;
    set<string> inserted;
};

#endif