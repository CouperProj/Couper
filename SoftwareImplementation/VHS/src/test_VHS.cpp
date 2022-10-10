#include "VHS.h"
#include "mylibpcap.h"
#include "util.h"
#include <iostream>
#include <set>
#include <memory>
#include <algorithm>
#include <fstream>
#include <unistd.h>
#include <unordered_map>
#include <ctime>
using std::unique_ptr;

#define TEST_PERFLOW_SPREAD 1

int main(){
    string filename = "MAWI.pcap";
    FILE_HANDLER filehandler(filename);
    uint32_t mem = 1000;
    VHS vhs(mem);         
    
    string flowID, elemID;
    while(int status = filehandler.get_item(flowID, elemID)){
        vhs.process_packet(flowID, elemID);
        if(filehandler.proc_num()%5000000 == 0)
            break;
            // cout<<"process packet "<<filehandler.proc_num()<<endl;
    }
#ifdef TEST_PERFLOW_SPREAD
    string flow_query = "192168000001";  //an example
    uint32_t ans = vhs.get_flow_cardinality(flow_query);
#endif
    
    return 0;
}
