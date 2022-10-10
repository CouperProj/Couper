#include "cds.h"
#include "mylibpcap.h"
#include <ctime>
#include <unordered_map>

#define OUTPUT_SUPERSPREADERS 1

int main()
{
    string filename = "MAWI.pcap";
    FILE_HANDLER filehandler(filename);
    uint32_t total_mem = 30*1024;
    uint32_t cp_mem = 0;    // when cp_mem > 0, CDS is improved by Couper:layer1.
    double cp_ratio = (double)cp_mem/total_mem;    
    CDS* cds = new CDS(total_mem, cp_ratio); 

    // insertion stage
    string flowID, elemID;
    while(int status = filehandler.get_item(flowID, elemID)){
        cds->process_packet(flowID, elemID);
    }

    // recovery stage
    vector<IdSpread> superspreaders;      
    cds->DetectSuperSpreaders(superspreaders);
#ifdef OUTPUT_SUPERSPREADERS
    string ofile_path = "../../CDS/output/SuperSpreaders";
    write_superspreaders(ofile_path, superspreaders);
#endif
            
    return 0;
}