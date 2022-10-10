#include"VHS.h"
#include"math.h"

namespace regOP{
    uint32_t bits_bias;
    uint32_t uint32_pos;
    uint32_t inner_bias;
    int shift_;
    vector<uint64_t> zero_patterns(64);
}

VHS::VHS(uint32_t mem): global_HLL(glb_HLL_size){
    memory = mem;  //kB
    register_num = memory * 1024 * 8 / 5;
    raw.resize(memory * 1024 * 8 / 32 + 1);
    uint64_t allone = -1;
    uint64_t fiveone = 31;
    for(size_t i = 0;i < 59;i++){
        regOP::zero_patterns[i] = allone ^ (fiveone << (59-i));
    }
}

uint8_t VHS::get_register(uint32_t reg_pos){
    using namespace regOP;
    bits_bias = reg_pos * register_size;
    uint32_pos =  bits_bias / 32;
    inner_bias = bits_bias % 32;

    uint64_t tmp = (static_cast<uint64_t>(raw[uint32_pos])<<32) + raw[uint32_pos+1];
    uint8_t ans = (tmp >> (64 - inner_bias - 5)) & 31;
    return ans;
}

void VHS::set_register(uint32_t reg_pos, uint8_t val){
    using namespace regOP;
    uint64_t tmp = (static_cast<uint64_t>(raw[uint32_pos]) << 32) + raw[uint32_pos + 1];
    tmp &= zero_patterns[inner_bias];
    tmp |= static_cast<uint64_t>(val)<<(59-inner_bias);
    raw[uint32_pos] = static_cast<uint32_t>(tmp >> 32);
    raw[uint32_pos + 1] = static_cast<uint32_t>(tmp);
}

void VHS::process_packet(string flowID, string elementID){
    // uint32_t hash_flow = str_hash32(flowID, HASH_SEED_1);
    uint32_t hash_eleID = str_hash32(elementID, HASH_SEED_1);
    uint32_t reg_pos = str_hash32(flowID + to_string(hash_eleID & (HLL_size - 1)), HASH_SEED_2) % register_num;
    uint8_t init_val = get_register(reg_pos);
    uint8_t rou_x = get_leading_zeros(hash_eleID) + 1;
    if(rou_x > init_val)
        set_register(reg_pos, rou_x);

    uint32_t hash_flowele = str_hash32(flowID + elementID, HASH_SEED_1);
    init_val = global_HLL[hash_flowele & (glb_HLL_size - 1)];
    rou_x = get_leading_zeros(hash_flowele) + 1;
    if(init_val < rou_x)
        global_HLL[hash_flowele & (glb_HLL_size - 1)] = rou_x;

    // detect superspreaders
    if(DETECT_SUPERSPREADER == false)
        return;
    uint32_t flowsrpead = get_flow_cardinality(flowID);
    IdSpread tmpflow;
    tmpflow.flowID = flowID;  tmpflow.spread = flowsrpead;
    if(inserted.find(flowID) != inserted.end()){
        for(auto iter = heap.begin();iter != heap.end();iter++){
            if(iter->flowID == flowID){
                iter->spread = flowsrpead;
                make_heap(iter, heap.end(), MinHeapCmp());
                break;
            }
        }
        return;
    }    
    if(heap.size() < heap_size){
        heap.push_back(tmpflow);
        inserted.insert(flowID);
    } else {
        std::push_heap(heap.begin(), heap.end(), MinHeapCmp());
        if(flowsrpead >= heap[0].spread){
            inserted.erase(heap[0].flowID);
            pop_heap(heap.begin(), heap.end(), MinHeapCmp());
            heap.pop_back();
            heap.push_back(tmpflow);
            std::push_heap(heap.begin(), heap.end(), MinHeapCmp());
            inserted.insert(flowID);
        }
    }
}

uint32_t VHS::get_spread(vector<uint8_t> virtual_HLL){
    uint32_t tmpsize = virtual_HLL.size();
    double alpha_m = 0.7213/(1+1.079/tmpsize); 
    double inv_sum = 0;
    for(size_t i = 0;i < tmpsize;i++)
        inv_sum += pow(2,0-virtual_HLL[i]);
    double E = alpha_m * tmpsize * tmpsize / inv_sum;
    if(E <= 2.5 * tmpsize){
        uint32_t zeros_num = 0;
        for(size_t i = 0;i < virtual_HLL.size();i++){
            if(virtual_HLL[i] == 0)
                zeros_num++;
        }
        E = tmpsize * log((double)tmpsize/zeros_num);
    }
    return static_cast<uint32_t>(E);
}

int VHS::get_flow_cardinality(string flowID){
    vector<uint8_t> virtual_HLL(HLL_size);
    for(size_t i = 0;i < HLL_size;i++){
        uint32_t reg_pos = str_hash32(flowID + to_string(i), HASH_SEED_2) % register_num;
        virtual_HLL[i] = get_register(reg_pos);
    }
    double ns_hat = get_spread(virtual_HLL);
    double m = register_num, s = HLL_size;
    double n_hat = get_spread(global_HLL);
    double ans = m * s / (m - s) * (ns_hat/s - n_hat/m);
    if (ans < 1)
        ans = 1;
    return ans;
}