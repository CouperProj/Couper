#include "rerskt.h"

uint8_t HLL::get_leading_zeros(uint32_t bitstr){
    for(size_t i = 1;i <= 32;i++)
    {
        if( ((bitstr<<i)>>i) != bitstr )
            return i - 1;
    }
    return 32;
}

void HLL::record_element(uint32_t hash_elem, uint32_t unit_pos){
    uint8_t lz_num = get_leading_zeros(hash_elem) + 1;
    HLL_registers[unit_pos] = max(lz_num , HLL_registers[unit_pos]);
}

int HLL::get_spread(array<uint8_t,HLL::register_num> virtual_HLL){
    double inv_sum = 0;
    for(size_t i = 0;i < virtual_HLL.size();i++)
        inv_sum += pow(2,0-virtual_HLL[i]);
    double E = alpha_m * 128 * 128 / inv_sum;
    if(E <= 2.5 * 128){
        uint32_t zeros_num = 0;
        for(size_t i = 0;i < virtual_HLL.size();i++){
            if(virtual_HLL[i] == 0)
                zeros_num++;
        }
        E = 128 * log((double)128/zeros_num);
    }
    return (int)E;
}

void HLL::reset(){
    for(size_t i = 0;i < HLL_registers.size();i++)
        HLL_registers[i] = 0;
}

void HLL::set_unit(uint32_t pos,uint32_t val){
    HLL_registers[pos] = val;
}

int HLL::get_spread(){
    return get_spread(HLL_registers);
}

void Bitmap::reset(){
    for(size_t i = 0;i < raw.size();i++)
        raw[i] = 0;
}

void Bitmap::record_element(uint32_t hash_elem, uint32_t unit_pos){
    uint32_t bitmap_pos = unit_pos / 8;
    raw[bitmap_pos] |= 1 << (7 - (unit_pos % 8));
}

uint32_t Bitmap::get_unitval(uint32_t bitpos){
    uint32_t bitmap_pos = bitpos / 8;
    uint32_t res =  1 & (raw[bitmap_pos] >> (7 - (bitpos % 8)));
    return res;
}

void Bitmap::set_unit(uint32_t pos,uint32_t val){
    uint32_t bitmap_pos = pos / 8;
    raw[bitmap_pos] |= val << (7 - (pos % 8));
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

uint32_t getbit(array<uint64_t,2> hashres128,uint32_t pos){
    uint32_t retbit;
    if(pos < 64)
        retbit = (hashres128[0] & ( static_cast<uint64_t>(1) << (64 - pos - 1) ) ) == 0 ? 0 : 1; 
    else
        retbit = (hashres128[1] & ( static_cast<uint64_t>(1) << (128 - pos - 1) ) ) == 0 ? 0 : 1; 
    return retbit;
}

template<class Estimator>
RerSkt<Estimator>::RerSkt(uint32_t memory_): memory(memory_), table_size(memory * 1024 * 8 / 2 /Estimator::size),
table1(table_size), table2(table_size) {
    for(size_t i = 0; i < table1.size();i++){
        table1[i].reset();
        table2[i].reset();
    }
}

template<class Estimator>
void RerSkt<Estimator>::process_packet(string flowid, string element){
    uint32_t flow_hash = str_hash32(flowid,HASH_SEED_1);
    uint32_t Estimator_pos = flow_hash % table_size;
    uint32_t elem_hash = str_hash32(element,HASH_SEED_2);
    uint32_t unit_index = elem_hash % table1[0].get_unit_num();
    uint32_t hash_batch = unit_index / 128;
    array<uint64_t,2> hashres_128 = str_hash128(flowid + to_string(hash_batch), HASH_SEED_1);
    uint32_t table_num = getbit(hashres_128, unit_index % 128);
    if(table_num == 0) 
        table1[Estimator_pos].record_element(elem_hash, unit_index);
    else
        table2[Estimator_pos].record_element(elem_hash, unit_index);

    //detect superspreaders with piggyback
    if(DETECT_SUPERSPREADER == false)
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
int RerSkt<Estimator>::get_flow_cardinality(string flowid){
    uint32_t hashres_32 = str_hash32(flowid, HASH_SEED_1);
    uint32_t Estimator_pos = hashres_32 % table_size;
    Estimator primary_est;
    Estimator complement_est;

    array<uint64_t,2> hashres_128;
    for(size_t i = 0;i < primary_est.get_unit_num();i++){
        uint32_t modval = i % 128;
        if(modval == 0)
            hashres_128 = str_hash128(flowid + to_string(i / 128),HASH_SEED_1);
        uint32_t table_num = getbit(hashres_128, modval);
        if(table_num == 0){
            primary_est.set_unit(i,table1[Estimator_pos].get_unitval(i));
            complement_est.set_unit(i,table2[Estimator_pos].get_unitval(i));
        } else {
            primary_est.set_unit(i,table2[Estimator_pos].get_unitval(i));
            complement_est.set_unit(i,table1[Estimator_pos].get_unitval(i));
        }
    }
    int pri_spread = primary_est.get_spread();
    int comp_spread = complement_est.get_spread();
    int flow_spread = pri_spread - comp_spread;
    if (flow_spread < 0)
        flow_spread = 0;
    return flow_spread;
}

template class RerSkt<Bitmap>;
template class RerSkt<HLL>;