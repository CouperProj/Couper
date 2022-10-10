#include "mylibpcap.h"
#include "rerskt.h"
#include <iostream>
#include <set>
#include <memory>
#include <algorithm>
#include <fstream>
#include <unistd.h>
#include <ctime>
#include <string>
#include "util.h"

#define TEST_PERFLOW_SPREAD 1

int main() {
    string filename = "MAWI.pcap";
    FILE_HANDLER filehandler(filename);
    uint32_t mem = 1000;
    RerSkt<HLL> rerskt(mem);           //  use HLL as basic Estimator
    // RerSkt<Bitmap> rerskt(mem);     //  use Bitmap as basic Estimator    
    
    string flowID, elemID;
    while(int status = filehandler.get_item(flowID, elemID)){
        rerskt.process_packet(flowID, elemID);
        if(filehandler.proc_num()%5000000 == 0)
            cout<<"process packet "<<filehandler.proc_num()<<endl;
    }
#ifdef TEST_PERFLOW_SPREAD
    string flow_query = "192168000001";  //an example
    uint32_t ans = rerskt.get_flow_cardinality(flow_query);
#endif

    return 0;
}

