#include "Vector_BF.h"
#include "mylibpcap.h"
#include <ctime>
#include <unordered_map>

#define OUTPUT_SUPERSPREADERS 1

int main()
{
    string filename = "MAWI.pcap";
    FILE_HANDLER filehandler(filename);
    uint32_t total_mem = 30*1024;
    uint32_t cp_mem = 0;  // when cp_mem > 0, VBF is improved by Couper:layer1.
    double cp_ratio = (double)cp_mem/total_mem;    
    Vector_Bloom_Filter* vbf = new Vector_Bloom_Filter(total_mem, cp_ratio);   
    
    // insertion stage
    string flowID, elemID;
    while(int status = filehandler.get_item(flowID, elemID)){
        array<uint8_t,4> srcip_tuple;
        for(size_t i = 0;i < 4;i++){
            srcip_tuple[i] = atoi(flowID.substr(i*3,3).c_str());
        }            
        vbf->process_packet(flowID,srcip_tuple,elemID);
    }
    
    // recovery stage
    uint32_t threshold = 1300;
    vbf->calc_Z(threshold);
    vector<IdSpread>* superspreaders = new vector<IdSpread>;
    vbf->Detect_Superpoint(superspreaders);
#ifdef OUTPUT_SUPERSPREADERS
    string ofile_path = "../../Vector_BF/output/SuperSpreaders";
    write_superspreaders(ofile_path, *superspreaders);
#endif
    return 0;
}
