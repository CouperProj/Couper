#ifndef SPREAD_SKETCH_H
#define SPREAD_SKETCH_H

#include <iostream>
#include <math.h>
#include <vector>
#include <set>
#include <algorithm>
#include "hashfunc.h"
#include "util.h"
#include "Couper.h"

using namespace std;

class MultiResolutionBitmap{
public:
    static constexpr double sigma = 0.1;
    static const uint32_t b = 0.6367 / (sigma * sigma);
    static const uint32_t b_hat = 2 * b;
    static const uint32_t C = 120000;
    static const uint32_t c = 2 + 10;   //log2(C / (2.6744 * b)); == 9.47
    static constexpr double setmax_ratio = 0.9311;
    static const uint32_t mrbitmap_size = b * (c - 1) + b_hat;
    vector<vector<uint8_t>> V;
    MultiResolutionBitmap();    
    uint32_t get_ones_num(uint32_t layer);
    void update(uint32_t l, uint32_t setbit);
    uint32_t get_cardinality();
};

class SS_Bucket{
public:
    string K;
    uint32_t L = 0;
    MultiResolutionBitmap mrbitmap;
    static const uint32_t bkt_size = 32 + 32 + MultiResolutionBitmap::mrbitmap_size;
};


class SpreadSketch{
public:
    //Couper: Filter
    Bitmap_Arr Couper_bm;
    bool use_Couper = true;
    //SpreadSketch
    static const uint32_t r = 4;
    uint32_t w;
    vector<vector<SS_Bucket>> bkt_table;

public:
    SpreadSketch(uint32_t mem, double cmratio);
    void update(string flowid, string elementid);
    uint32_t query(string flowid);
    void report_superspreaders(vector<IdSpread>& superspreaders);
};

#endif