#include <iostream>
#include "Couper.h"
#include <malloc.h>
#include <bitset>
#include <vector>
#include <algorithm>
#include <fstream>

namespace metadata_1{
    uint32_t bits_bias;
    uint32_t uint32_pos;
    uint32_t inner_bias;
    int shift_;
};

namespace metadata_2{
    uint32_t bits_bias;
    uint32_t uint32_pos;
    uint32_t inner_bias;
    int shift_;
};

Bitmap_Arr::Bitmap_Arr(uint32_t memory_): memory(memory_), bitmap_num(memory * 1024 * 8 / bitmap_size), raw(memory*1024*8/32) {
    for(size_t i = 0;i < raw.size();i++) raw[i] = 0;
    for(size_t i = 0;i < bitmap_size;i++) patterns[i] = 1 << i;
    
    double ln_bmsize = log(bitmap_size);
    double ln_bmsize_minu1 = log(bitmap_size - 1);

    // for(size_t i = 1;i <= bitmap_size;i++) cardinalitys[i] = ( ln_bmsize - log(i) ) / (ln_bmsize - ln_bmsize_minu1);
    for(size_t i = 1;i <= bitmap_size;i++) card_dict[i] = bitmap_size * log(bitmap_size / static_cast<double>(i));
    card_dict[0] = card_dict[1]; 

    cout<< "The number of LC(bitmap)s in layer 1: " << bitmap_num << endl;
}

uint32_t Bitmap_Arr::get_bitmap_1(uint32_t bitmap_pos){
    using namespace metadata_1;
    bits_bias = bitmap_pos * bitmap_size;
    uint32_pos =  bits_bias / 32;
    inner_bias = bits_bias % 32;
    uint32_t end_bit_idx = inner_bias + bitmap_size - 1;
    uint32_t res;
    if (end_bit_idx < 32) {
        res = raw[uint32_pos] >> inner_bias;
    } else {
        res = (raw[uint32_pos + 1] << (32 - inner_bias)) + (raw[uint32_pos] >> inner_bias);
    }
    res &= FULL_PAT;
    return res;
}

uint32_t Bitmap_Arr::get_bitmap_2(uint32_t bitmap_pos){
    using namespace metadata_2;
    bits_bias = bitmap_pos * bitmap_size;
    uint32_pos =  bits_bias / 32;
    inner_bias = bits_bias % 32;
    uint32_t end_bit_idx = inner_bias + bitmap_size - 1;
    uint32_t res;
    if (end_bit_idx < 32) {
        res = raw[uint32_pos] >> inner_bias;
    } else {
        res = (raw[uint32_pos + 1] << (32 - inner_bias)) + (raw[uint32_pos] >> inner_bias);
    }
    res &= FULL_PAT;
    return res;
}

bool Bitmap_Arr::check_flow_full(array<uint64_t,2>& hash_flowid){
    uint32_t esti_pos_1, esti_pos_2;
    esti_pos_1 = static_cast<uint32_t>(hash_flowid[0]>>32) % bitmap_num;
    esti_pos_2 = static_cast<uint32_t>(hash_flowid[0]) % bitmap_num;
    uint32_t bitmap1 = get_bitmap_1(esti_pos_1);
    uint32_t bitmap2 = get_bitmap_2(esti_pos_2);
    uint32_t bitmap_merged = bitmap1 & bitmap2;
    bitset<bitmap_size> bm(bitmap_merged);
    if (bm.count() < capacity)
        return false;
    else
        return true;
}

bool Bitmap_Arr::set_bit_1(uint32_t bit_pos){
    using namespace metadata_1;
    uint32_t temp = inner_bias + bit_pos;
    if(temp <= 31)
        raw[uint32_pos] |= (1<<temp); 
    else{
        temp -= 32;
        raw[uint32_pos + 1] |= (1<<temp); 
    }
    return false;
}

bool Bitmap_Arr::set_bit_2(uint32_t bit_pos){
    using namespace metadata_2;
    uint32_t temp = inner_bias + bit_pos;
    if(temp <= 31)
        raw[uint32_pos] |= (1<<temp); 
    else{
        temp -= 32;
        raw[uint32_pos + 1] |= (1<<temp); 
    }
    return false;
}

bool Bitmap_Arr::process_packet(array<uint64_t,2>& hash_flowid, uint32_t l2_update_pos){
    if (check_flow_full(hash_flowid))
        return true;
    uint32_t update_bit = l2_update_pos % bitmap_size;
    set_bit_1(update_bit);
    set_bit_2(update_bit);
    return false;
}

bool Bitmap_Arr::process_packet(array<uint64_t,2>& hash_flowid, array<uint64_t,2>& hash_element) {
    if (check_flow_full(hash_flowid))
        return true;
    uint32_t update_bit = (hash_element[1]>>32) % bitmap_size;
    set_bit_1(update_bit);
    set_bit_2(update_bit);
    return false;
}

int Bitmap_Arr::get_cardinality(string flowid, array<uint64_t,2>& hash_flowid, uint32_t& bm_merged){
    uint32_t esti_pos_1, esti_pos_2;
    esti_pos_1 = static_cast<uint32_t>(hash_flowid[0]>>32) % bitmap_num;
    esti_pos_2 = static_cast<uint32_t>(hash_flowid[0]) % bitmap_num;
    uint32_t bm1 = get_bitmap_1(esti_pos_1);
    uint32_t bm2 = get_bitmap_2(esti_pos_2);
    bm_merged = bm1 & bm2;
    bitset<bitmap_size> bm_bits(bm_merged);
    size_t zeros_num = bitmap_size - bm_bits.count();
    if (bm_bits.count() < capacity)
        return card_dict[zeros_num];
    else
        return BITMAP_FULL_FLAG;
}

//HyperLogLog Estimator
uint32_t HyperLogLog::get_size(){
    return HLL_size;
}

void HyperLogLog::shared_param_Init(){
    for(size_t i = 0;i < exp_table.size();i++) exp_table[i] = pow(2.0, 0.0 - i);
    if (register_num == 32) alpha_m = 0.697; 
    else if (register_num == 64) alpha_m = 0.709;
    else if (register_num >= 128) alpha_m = 0.7213/(1 + 1.079/register_num);
    alpha_m_sqm = alpha_m * register_num * register_num; 
    LC_thresh = 2.5 * register_num; 
    cout << "HyperLogLog shared params initialized." << endl;
}

HyperLogLog::HyperLogLog() : HLL_raw(register_num) {
    digest = 0;    
}

uint32_t HyperLogLog::get_counter_val(uint32_t index){
    uint32_t uint8_pos = index / 2;
    if(uint8_pos % 2 == 0)
        return HLL_raw[uint8_pos] >> 4;       //high 4 bits
    else
        return HLL_raw[uint8_pos] & 15;       //low 4 bits
}

int HyperLogLog::try2update_counter(uint32_t index, uint32_t val_){
    uint32_t uint8_pos = index / 2;
    uint32_t old_val, new_val;
    if(index % 2 == 0){
        old_val = HLL_raw[uint8_pos] >> 4;   //read the high 4 bits
        new_val = static_cast<uint8_t>(val_) << 4;
        if (new_val > old_val) {
            HLL_raw[uint8_pos] &= 15;            //keep the low 4 bits unchanged 
            HLL_raw[uint8_pos] |= new_val;       //set the high 4 bits
        }
    } else {
        old_val = HLL_raw[uint8_pos] & 15;   //read the low 4 bits
        new_val = static_cast<uint8_t>(val_);
        if (new_val > old_val) {
            HLL_raw[uint8_pos] &= 240;            //keep the high 4 bits unchanged 
            HLL_raw[uint8_pos] |= new_val;
        }
    }
    if (new_val > old_val) {
        digest += (new_val - old_val);
        return digest;
    }
    return 0;
}

int HyperLogLog::update(uint32_t bitstr, uint32_t inner_update_pos){
    uint32_t index = inner_update_pos; //bitstr & (register_num - 1);
    uint32_t rou_x = get_leading_zeros(bitstr) + 1;
    return try2update_counter(index, rou_x);
}

int HyperLogLog::query(){
    double res;
    double sum_ = 0;
    uint32_t V_ = 0;
    for(size_t i = 0;i < register_num;i++){
        uint32_t tmpval = get_counter_val(i);
        sum_ += exp_table[tmpval];
        if(tmpval == 0)
            V_++;
    }
    res = alpha_m_sqm / sum_;
    if(res <= LC_thresh)
        if(V_ > 0)
            res = register_num * log(register_num / (double)V_);
    return round(res);
}

HyperLogLog HyperLogLog::query_merged_Estimator(HyperLogLog& HLL1, HyperLogLog& HLL2){
    HyperLogLog hll_merged;
    for(size_t i = 0;i < register_num;i++){
        uint32_t tmpval = min(HLL1.get_counter_val(i), HLL2.get_counter_val(i));
        hll_merged.try2update_counter(i, tmpval);
    }
    return hll_merged;
}

uint32_t HyperLogLog::generate_bitmap(){
    bitset<Bitmap_Arr::bitmap_size> bm2;
    for (size_t i = 0;i < LEN;i++){
        if (get_counter_val(i) > 0)
            bm2.set(i % Bitmap_Arr::bitmap_size);
    }
    return bm2.to_ulong();
}

uint32_t MultiResBitmap::get_size(){
    return mrbitmap_size;
}

void MultiResBitmap::shared_param_Init(){
    c = 2 + ceil(log2(C / (2.6744 * b)));
    mrbitmap_size = b * (c - 1) + b_hat;
    cout << "MultiResBitmap shared params initialized.  " << "mrbitmap_size: " << mrbitmap_size << endl;
}

MultiResBitmap::MultiResBitmap(){
    bitmaps.resize(c);
    uint32_t uint8num = ceil(b/8.0);
    for(size_t i = 0;i < c - 1;i++)
        bitmaps[i].resize(uint8num);
    uint8num = ceil(b_hat/8.0);
    bitmaps[c - 1].resize(uint8num);
    digest = 0;
}

uint32_t MultiResBitmap::get_ones_num(uint32_t layer){
    auto tmpbitmap = bitmaps[layer];
    uint32_t setbit_num = 0;
    for(size_t i = 0;i < tmpbitmap.size();i++){
        setbit_num += get_one_num(tmpbitmap[i]);
    }
    return setbit_num;
}

int MultiResBitmap::update(uint32_t bitstr, uint32_t inner_update_pos){
    uint32_t l = get_leading_zeros(bitstr);
    uint32_t setbit;
    if(l < MultiResBitmap::c - 1)
        setbit = inner_update_pos;
    else
        setbit = bitstr % MultiResBitmap::b_hat;
    if(l < c - 1){
        bitmaps[l][setbit / 8] |= (128 >> (setbit % 8));
    } else {
        bitmaps[c - 1][setbit / 8] |= (128 >> (setbit % 8));
    }
    if (digest < l) {
        digest = l;
        return digest;
    }
    return 0;
}

int MultiResBitmap::query(){
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

MultiResBitmap MultiResBitmap::query_merged_Estimator(MultiResBitmap& mrb1, MultiResBitmap& mrb2){
    MultiResBitmap mrb_merged;
    for (size_t i = 0;i < c;i++){
        for (size_t j = 0;j < mrb_merged.bitmaps[i].size();j++){
            mrb_merged.bitmaps[i][j] = mrb1.bitmaps[i][j] & mrb2.bitmaps[i][j];
        }        
    }
    return mrb_merged;
}

uint32_t MultiResBitmap::generate_bitmap(){
    bitset<Bitmap_Arr::bitmap_size> bm;
    vector<uint8_t> multi_layer_merged(bitmaps[0].size());
    for (size_t i = 0;i < multi_layer_merged.size();i++){
        uint8_t tmp = 0;
        for (size_t layer = 0;layer < c - 1;layer++)
            tmp |= bitmaps[layer][i];
        multi_layer_merged[i] = tmp;
    }
    for (size_t i = 0;i < multi_layer_merged.size();i++){
        uint32_t tmp = multi_layer_merged[i];
        for (size_t j=0;j<8;j++){
            if ( tmp & (128>>j) == 1 ){
                bm.set( (i*8 + j) % Bitmap_Arr::bitmap_size );
            }
        }
    }
    return bm.to_ulong();
}

template<class EstimatorType>
Layer2<EstimatorType>::Layer2(uint32_t memory_) : memory(memory_), hash_table(tab_size){
    EstimatorType::shared_param_Init();
    uint32_t esti_size = EstimatorType::get_size();
    esti_num = memory_ * 8 * 1024 / esti_size;
    estimators.resize(esti_num);
}

template<class EstimatorType>
int Layer2<EstimatorType>::get_inner_update_pos(uint32_t hashres32){
    inner_update_pos = hashres32 % EstimatorType::LEN;
    return inner_update_pos;
}

template<class EstimatorType>
void Layer2<EstimatorType>::process_packet(string flowid, array<uint64_t,2>& hash_flowid, uint32_t hashres32){
    uint32_t esti_pos_1, esti_pos_2;
    esti_pos_1 = static_cast<uint32_t>(hash_flowid[1] >> 32) % esti_num;
    esti_pos_2 = static_cast<uint32_t>(hash_flowid[1]) % esti_num;
    int dg1 = estimators[esti_pos_1].update(hashres32, inner_update_pos);
    int dg2 =  estimators[esti_pos_2].update(hashres32, inner_update_pos);
    int flow_digest = max(dg1, dg2);
    if (flow_digest > 0){
        insert_hashtab(flowid, flow_digest, hash_flowid[0]);
    }
}

template<class EstimatorType>
uint32_t Layer2<EstimatorType>::get_cardinality(string flowid, array<uint64_t,2>& hash_flowid, uint32_t& layer2_bm){
    uint32_t esti_pos_1, esti_pos_2;
    esti_pos_1 = static_cast<uint32_t>(hash_flowid[1] >> 32) % esti_num;
    esti_pos_2 = static_cast<uint32_t>(hash_flowid[1]) % esti_num;
    EstimatorType merged_estimator = EstimatorType::query_merged_Estimator(estimators[esti_pos_1],
        estimators[esti_pos_2]);
    layer2_bm = merged_estimator.generate_bitmap();
    return merged_estimator.query();
}

template<class EstimatorType>
void Layer2<EstimatorType>::insert_hashtab(string flowid, int flow_digest, uint64_t hahsres64){     // Power of Two
    uint32_t hashres32 = hahsres64 >> 32;         //high 32 bits of initial hash result which is 64 bits
    uint32_t table_pos1 = (hashres32 >> 16) % tab_size;     //high 16 bits
    uint32_t table_pos2 = (hashres32 & MAX_UINT16) % tab_size;  //low 16 bits

    if(hash_table[table_pos1].flowid == "" || hash_table[table_pos1].flowid == flowid){
        hash_table[table_pos1].flowid = flowid;
        hash_table[table_pos1].digest = flow_digest;
        return;
    }
    else if(hash_table[table_pos2].flowid == "" || hash_table[table_pos2].flowid == flowid){
        hash_table[table_pos2].flowid = flowid;
        hash_table[table_pos2].digest = flow_digest;
        return;
    }

    uint16_t tmp1 = hash_table[table_pos1].digest;
    uint16_t tmp2 = hash_table[table_pos2].digest; 
    if(tmp1 > tmp2){
        if(flow_digest >= tmp2){
            hash_table[table_pos2].flowid = flowid;
            hash_table[table_pos2].digest = flow_digest;
        }
    } else {
        if(flow_digest >= tmp1){
            hash_table[table_pos1].flowid = flowid;
            hash_table[table_pos1].digest = flow_digest;
        }
    }
}

void Couper::report_superspreaders(vector<IdSpread>& superspreaders){
    superspreaders.clear();
    set<string> checked_flows;
    for(size_t i = 0;i < layer2.tab_size;i++){
        string tmp_flowid = layer2.hash_table[i].flowid;
        if(checked_flows.find(tmp_flowid) != checked_flows.end())
            continue;
        else{
            checked_flows.insert(tmp_flowid);
            uint32_t esti_card = get_flow_cardinality(tmp_flowid); 
            superspreaders.push_back( IdSpread(tmp_flowid, esti_card) );
        }
    }
    sort(superspreaders.begin(), superspreaders.end(), IdSpreadComp);
}

uint32_t Couper::process_packet(string flowid, string element) {
    array<uint64_t,2> hash_flowid = str_hash128(flowid, HASH_SEED_1);
    array<uint64_t,2> hash_element = str_hash128(flowid + element, HASH_SEED_2);
    layer2.get_inner_update_pos(static_cast<uint32_t>(hash_element[0]));
    bool layer1_full = layer1.process_packet(hash_flowid, layer2.inner_update_pos);
    if(!layer1_full)
        return 1;
    layer2.process_packet(flowid, hash_flowid, static_cast<uint32_t>(hash_element[1]));
    return 2;
}

/* bias = |S1| + |S2| - |S1 union S2| */
// int Couper::get_overlapping_bias(uint32_t bm_layer1, uint32_t bm_layer2){
//     bitset<Bitmap_Arr::bitmap_size> bm_layer1_bits(bm_layer1);
//     bitset<Bitmap_Arr::bitmap_size> bm_layer2_bits(bm_layer2);
//     uint32_t bm_union = bm_layer1 | bm_layer2;
//     bitset<Bitmap_Arr::bitmap_size> bm_union_bits(bm_union);
//     uint32_t zero_1 = Bitmap_Arr::bitmap_size - bm_layer1_bits.count();
//     uint32_t zero_2 = Bitmap_Arr::bitmap_size - bm_layer2_bits.count();
//     uint32_t zero_union = Bitmap_Arr::bitmap_size - bm_union_bits.count();
//     int bias = layer1.card_dict[zero_1] + layer1.card_dict[zero_2] - layer1.card_dict[zero_union];   //Card(A inter B) = Card(A) + Card(B) - Card(A union B)
//     return bias;
// }

/* bias = |S1 inter S2| */
int Couper::get_overlapping_bias(uint32_t bm_layer1, uint32_t bm_layer2){
    uint32_t bm_intersection = bm_layer1 & bm_layer2;
    bitset<Bitmap_Arr::bitmap_size> bm_inter_bits(bm_intersection);
    uint32_t zero_inter = Bitmap_Arr::bitmap_size - bm_inter_bits.count();
    int bias = layer1.card_dict[zero_inter];   
    return bias;
}

uint32_t Couper::get_flow_cardinality(string flowid){
    array<uint64_t,2> hash_flowid = str_hash128(flowid, HASH_SEED_1);
    uint32_t layer1_bm;
    int cardinality_layer1 = layer1.get_cardinality(flowid, hash_flowid, layer1_bm);
    int ret;
    if(cardinality_layer1 != BITMAP_FULL_FLAG)
        ret = cardinality_layer1;
    else {
        uint32_t layer2_bm;
        int cardinality_layer2 = layer2.get_cardinality(flowid, hash_flowid, layer2_bm);
        int overlapping_bias = get_overlapping_bias(layer1_bm, layer2_bm);
        // cout << overlapping_bias << endl;
        if (overlapping_bias < 0)
            overlapping_bias = 0;
        ret = cardinality_layer2 + layer1.card_dict[Bitmap_Arr::bitmap_size - layer1.capacity] - overlapping_bias;
    }
    if (ret <= 0)
        ret = 1;
    return ret;
}

template class Layer2<HyperLogLog>;
template class Layer2<MultiResBitmap>;
array<double, 1<<HyperLogLog::register_size> HyperLogLog::exp_table;
double HyperLogLog::alpha_m, HyperLogLog::alpha_m_sqm, HyperLogLog::LC_thresh;
uint32_t MultiResBitmap::c, MultiResBitmap::mrbitmap_size;