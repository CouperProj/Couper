#ifndef _CDS_H_
#define _CDS_H_

#include<iostream>
#include<vector>
#include<array>
#include<math.h>
#include<algorithm>
#include<set>
#include"hashfunc.h"
#include"util.h"
#include"Couper.h"
using namespace std;

#define HASH_SEED 92317


class CDS{
public:
    //Couper: Filter
    Bitmap_Arr Couper_bm;
    bool use_Couper = true;
    //CDS
    array<uint64_t,3> mi = {16067, 16369, 16361};
    array<uint64_t,2> Mi = {mi[1], mi[0]};
    uint64_t M = mi[0] * mi[1];
    array<uint64_t,2> Mi_inverse;
    uint32_t v;
    static const uint32_t H = 2;
    static const uint32_t H_plus = 1;
    vector<vector<uint8_t>> data;
    vector<uint32_t> cols1;  //indexes of super columns
    vector<uint32_t> cols2;
    static constexpr double phi = 0.001;
    static const uint32_t ss_thresh = 1000;        //super column of superspreader
    static const uint32_t sc_thresh = 100;        //super column of superchanges
    static const uint64_t n = (static_cast<uint64_t>(1) << 32) - 1;
    static const uint64_t p = 4294967311;   //fixed prime larger than n.
    
public:
    CDS(uint32_t mem, double am_ratio); //kB
    uint32_t hash_funs(uint32_t i, uint32_t x);
    void process_packet(string flowid, string element);
    uint32_t get_cardinality(vector<uint8_t> vec);
    uint32_t get_cardinality(uint32_t x);
    void FindSuperCols();
    void GetInverse();
    void DetectSuperSpreaders(vector<IdSpread>& superspreaders);
    void DetectSuperChanges(CDS& prevCDS, vector<IdSpread>& superchanges);
};




#endif