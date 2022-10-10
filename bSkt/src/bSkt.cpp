#include "bSkt.h"

uint8_t HLL::get_leading_zeros(uint32_t bitstr){
    for(size_t i = 1;i <= 32;i++){
        if( ((bitstr<<i)>>i) != bitstr )
            return i - 1;
    }
    return 32;
}

void HLL::record_element(uint32_t hashres){
    uint8_t lz_num = get_leading_zeros(hashres) + 1;
    uint32_t reg_pos = hashres & (register_num - 1);
    HLL_registers[reg_pos] = max(lz_num , HLL_registers[reg_pos]);
}

int HLL::get_spread(){
    double inv_sum = 0;
    for(size_t i = 0;i < HLL_registers.size();i++)
        inv_sum += pow(2,0-HLL_registers[i]);
    double E = alpha_m * register_num * register_num / inv_sum;
    if(E <= 2.5 * register_num){
        uint32_t zeros_num = 0;
        for(size_t i = 0;i < HLL_registers.size();i++){
            if(HLL_registers[i] == 0)
                zeros_num++;
        }
        if(zeros_num == 0)
            zeros_num = 1;
        E = register_num * log((double)register_num/zeros_num);
    }
    return (int)E;
}

void Bitmap::reset(){
    for(size_t i = 0;i < raw.size();i++)
        raw[i] = 0;
}

void Bitmap::record_element(uint32_t hashres){
    uint32_t unit_pos = hashres % bitnum;
    uint32_t bitmap_pos = unit_pos / 8;
    raw[bitmap_pos] |= 1 << (7 - (unit_pos % 8));
}

uint32_t Bitmap::get_unitval(uint32_t bitpos){
    uint32_t bitmap_pos = bitpos / 8;
    uint32_t res =  1 & (raw[bitmap_pos] >> (7 - (bitpos % 8)));
    return res;
}

int Bitmap::get_spread(){
    uint32_t empty_bits = 0;
    for(size_t i = 0;i < bitnum;i++){
        uint32_t tmp = get_unitval(i);
        if(tmp == 0)
            empty_bits++;
    }
    empty_bits = empty_bits > 0 ? empty_bits : 1;
    double empty_frac = static_cast<double>(empty_bits) / bitnum;
    double card = bitnum * log(1 / empty_frac);
    return static_cast<int>(card);
}

template<class Estimator>
void bSkt<Estimator>::process_packet(string flowid, string element){
    //bSkt
    array<uint64_t,2> hash_flowid = str_hash128(flowid,HASH_SEED_1);
    array<uint64_t,2> hash_element = str_hash128(flowid + element,HASH_SEED_2);
    for(size_t i = 0;i < 4;i++){
        uint32_t tmp_flow_hash = static_cast<uint32_t>( hash_flowid[i/2] >> ( ((i+1) % 2) * 32 ) );
        uint32_t tmp_element_hash = static_cast<uint32_t>( hash_element[i/2] >> ( ((i+1) % 2) * 32 ) );
        uint32_t Estimator_pos = tmp_flow_hash % table_size;
        tables[i][Estimator_pos].record_element(tmp_element_hash);
    }
    
    if(DETECT_SUPERSPREADER == false)  //detect super spreaders with piggyback
        return;
    uint32_t flowsrpead = get_flow_cardinality(flowid);
    IdSpread tmpflow;
    tmpflow.flowID = flowid;  tmpflow.spread = flowsrpead;
    if(inserted.find(flowid) != inserted.end()){
        for(auto iter = heap.begin();iter != heap.end();iter++){
            if(iter->flowID == flowid){
                iter->spread = flowsrpead;
                make_heap(iter, heap.end(), MinHeapCmp());
                break;
            }
        }
        return;
    }    
    if(heap.size() < heap_size){
        heap.push_back(tmpflow);
        inserted.insert(flowid);
    } else {
        std::push_heap(heap.begin(), heap.end(), MinHeapCmp());
        if(flowsrpead >= heap[0].spread){
            inserted.erase(heap[0].flowID);
            pop_heap(heap.begin(), heap.end(), MinHeapCmp());
            heap.pop_back();
            heap.push_back(tmpflow);
            std::push_heap(heap.begin(), heap.end(), MinHeapCmp());
            inserted.insert(flowid);
        }
    }
}

template<class Estimator>
uint32_t bSkt<Estimator>::get_flow_cardinality(string flowid){
    //bSkt
    array<uint64_t,2> hash_flowid = str_hash128(flowid, HASH_SEED_1);
    uint32_t spread = 1<<30;
    for(size_t i = 0;i < 4;i++){
        uint32_t tmp_flow_hash = static_cast<uint32_t>( hash_flowid[i/2] >> ( ((i+1) % 2) * 32 ) );
        uint32_t Estimator_pos = tmp_flow_hash % table_size;
        uint32_t tmp = tables[i][Estimator_pos].get_spread();
        if(tmp < spread)
            spread = tmp;
    }
    return spread;
}

template class bSkt<HLL>;
template class bSkt<Bitmap>;