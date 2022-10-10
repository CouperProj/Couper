#include "SS.h"
#include <sstream>

uint32_t string2uint32(string str){
    uint32_t ret;
    stringstream sstr;
    sstr << str;
    sstr >> ret;
    return ret;
}

MultiResolutionBitmap::MultiResolutionBitmap(){
    V.resize(c);
    uint32_t uint8num = ceil(b/8.0);
    for(size_t i = 0;i < c - 1;i++)
        V[i].resize(uint8num);
    uint8num = ceil(b_hat/8.0);
    V[c - 1].resize(uint8num);
}

uint32_t MultiResolutionBitmap::get_ones_num(uint32_t layer){
    auto tmpbitmap = V[layer];
    uint32_t setbit_num = 0;
    for(size_t i = 0;i < tmpbitmap.size();i++){
        setbit_num += get_one_num(tmpbitmap[i]);
    }
    return setbit_num;
}

void MultiResolutionBitmap::update(uint32_t l, uint32_t setbit){
    if(l < c - 1){
        V[l][setbit / 8] |= (128 >> (setbit % 8));
    } else {
        V[c - 1][setbit / 8] |= (128 >> (setbit % 8));
    }
}

uint32_t MultiResolutionBitmap::get_cardinality(){
    int base = c - 2;
    while(base >= 0){
        uint32_t setmax;
        if(base == c - 1)
            setmax = b_hat * setmax_ratio;
        else
            setmax = b * setmax_ratio;
        if(get_ones_num(base) > setmax)
            break;
        base--;
    }
    base++;
    double m = 0;
    for(size_t i = base;i < c - 1;i++){
        m += b * log( static_cast<double>(b) / (b - get_ones_num(i) ) );
    }
    m += b_hat * log( static_cast<double>(b_hat) / (b_hat - get_ones_num(c - 1) ) );
    uint32_t factor = powf64(2,base);
    return static_cast<uint32_t>(factor * m);
}

SpreadSketch::SpreadSketch(uint32_t mem, double cmratio): Couper_bm(mem * cmratio){
    if(cmratio == 0)
        use_Couper = false;
    w = mem * (1 - cmratio) * 1024 * 8 / r / SS_Bucket::bkt_size;
    bkt_table.resize(r);
    for(size_t i = 0;i < r;i++)
        bkt_table[i].resize(w);
}

void SpreadSketch::update(string flowid, string elementid){
    array<uint64_t,2> hash_flowid = str_hash128(flowid, HASH_SEED_1);
    array<uint64_t,2> hash_element = str_hash128(flowid + elementid, HASH_SEED_2);
    if (use_Couper) {
        bool full_flag = Couper_bm.process_packet(hash_flowid, hash_element);
        if (full_flag == false)
            return;
    }
    uint32_t hashres32(hash_element[0]);  //str_hash32(flowid + elementid, HASH_SEED_1);
    array<uint64_t,2> hashres128(hash_flowid);  //str_hash128(flowid,HASH_SEED_2);
    array<uint32_t,4> hashres32_arr{hashres128[0]>>32, hashres128[0], hashres128[1]>>32, hashres128[1]}; 

    uint32_t l = get_leading_zeros(hashres32);
    uint32_t setbit;
    if(l < MultiResolutionBitmap::c - 1){
        setbit = hashres32 % MultiResolutionBitmap::b;
    } else {
        setbit = hashres32 % MultiResolutionBitmap::b_hat;
    }
    
    for(size_t i = 0;i < r;i++){
        uint32_t idx = hashres32_arr[i] % w; //str_hash32(flowid + to_string(i), HASH_SEED_2) % w;
        bkt_table[i][idx].mrbitmap.update(l, setbit);
        if(bkt_table[i][idx].L <= l){
            bkt_table[i][idx].K = flowid; //static_cast<uint32_t>(stoul(flowid));
            bkt_table[i][idx].L = l;
        }
    }
}

uint32_t SpreadSketch::query(string flowid){
    uint32_t ret_val = static_cast<uint32_t>(1)<<31;
    array<uint64_t,2> hash_flowid = str_hash128(flowid, HASH_SEED_1);
    array<uint64_t,2> hashres128(hash_flowid);  //str_hash128(flowid,HASH_SEED_2);
    array<uint32_t,4> hashres32_arr{hashres128[0]>>32, static_cast<uint32_t>(hashres128[0]), hashres128[1]>>32, static_cast<uint32_t>(hashres128[1])}; 
    for(size_t i = 0;i < r;i++){
        uint32_t idx = hashres32_arr[i] % w;  //str_hash32(flowid + to_string(i), HASH_SEED_2) % w;
        uint32_t tmp_card = bkt_table[i][idx].mrbitmap.get_cardinality();
        if(tmp_card < ret_val)
            ret_val = tmp_card;
    }
    return ret_val;
}

void SpreadSketch::report_superspreaders(vector<IdSpread>& superspreaders){
    superspreaders.clear();
    set<string> checked_flows;
    for(size_t row = 0;row < r;row++){
        for(size_t col = 0;col < w;col++){
            string tmp_K = bkt_table[row][col].K;
            if(checked_flows.find(tmp_K) != checked_flows.end())
                continue;
            else{
                checked_flows.insert(tmp_K);
                uint32_t esti_card = query(tmp_K); 
                superspreaders.push_back(IdSpread(tmp_K,esti_card));
            }
        }
    }
    sort(superspreaders.begin(), superspreaders.end(), IdSpreadComp);
}