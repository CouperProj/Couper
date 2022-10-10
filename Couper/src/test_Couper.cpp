#include "Couper.h"
#include "MurmurHash3.h"
#include "mylibpcap.h"
#include <iostream>
#include <fstream>
#include <ctime>
#include <set>
#include <memory>
#include <algorithm>
#include <unordered_map>
#include <unistd.h>
using std::unique_ptr;

#define TEST_PERFLOW_SPREAD 1
#define OUTPUT_SUPERSPREADERS 1

int main() {
    string filename = "MAWI.pcap";
    FILE_HANDLER filehandler(filename);
    uint32_t mem = 1000;
    Couper Couper(mem, 0.6);
    
    string flowID, elemID;
    while(int status = filehandler.get_item(flowID, elemID)){
        Couper.process_packet(flowID, elemID);
        if(filehandler.proc_num()%5000000 == 0)
            cout<<"process packet "<<filehandler.proc_num()<<endl;
    }
#ifdef TEST_PERFLOW_SPREAD
    string flow_query = "192168000001";  //an example
    uint32_t ans = Couper.get_flow_cardinality(flow_query);
#endif
#ifdef OUTPUT_SUPERSPREADERS
    vector<IdSpread> superspreaders;
    Couper.report_superspreaders(superspreaders);
    string ofile_path = "../../Couper/output/SuperSpreaders";
    write_superspreaders(ofile_path, superspreaders);
#endif
    return 0;
}
