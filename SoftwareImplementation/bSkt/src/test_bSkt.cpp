#include "hashfunc.h"
#include "mylibpcap.h"
#include "bSkt.h"
#include <iostream>
#include <set>
#include <memory>
#include <algorithm>
#include <fstream>
#include <unistd.h>
#include <ctime>
using std::unique_ptr;

#define TEST_PERFLOW_SPREAD 1

int main()
{
    string filename = "MAWI.pcap";
    FILE_HANDLER filehandler(filename);
    uint32_t mem = 1000;
    bSkt<HLL> bskt(mem);           //  use HLL as basic Estimator
    // bSkt<Bitmap> bskt(mem);     //  use Bitmap as basic Estimator    
    
    string flowID, elemID;
    while(int status = filehandler.get_item(flowID, elemID)){
        bskt.process_packet(flowID, elemID);
        if(filehandler.proc_num() % 5000000 == 0)
            cout<<"process packet "<<filehandler.proc_num()<<endl;
    }
#ifdef TEST_PERFLOW_SPREAD
    string flow_query = "192168000001";  //an example
    uint32_t ans = bskt.get_flow_cardinality(flow_query);
#endif

    return 0;
}


// void write_superspreaders(string dataset, string filename, vector<IdSpread>& superspreaders){
//     string ofile_path = "../../bSkt/SuperSpreader/" + dataset + "/";
//     ifstream ifile_hand;
//     ofstream ofile_hand;
//     ofile_hand = ofstream(ofile_path + filename + ".txt");
//     if(!ofile_hand){
//         cout<<"fail to open files."<<endl;
//         return;
//     }
//     bool first_line = true;
//     for(auto item : superspreaders){
//         if(first_line)
//             first_line = false;
//         else
//             ofile_hand << endl;    
//         ofile_hand << item.flowID << " " << item.spread;
//     }
//     ofile_hand.close();
// }