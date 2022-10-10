// Hash table
#define HASH_TBL_SIZE     1024
#define HASH_CELL1_SIZE   32   // Size of IPv4 addr
#define HASH_CELL2_SIZE   HLL_SUM_WIDTH // 16

typedef bit<HASH_CELL1_SIZE> HASH_CELL1_T;
typedef bit<HASH_CELL2_SIZE> HASH_CELL2_T;

// ---------------------------------------------------------------------------
// Extern definition
// ---------------------------------------------------------------------------
Register<HASH_CELL1_T, INDEX_WIDTH16>(HASH_TBL_SIZE) hash_table_flow; // Flow id
Register<HASH_CELL2_T, INDEX_WIDTH16>(HASH_TBL_SIZE) hash_table_ps; // Partial sum
Hash<bit<16>>(HashAlgorithm_t.CRC16) hash_light;

// ---------------------------------------------------------------------------
// Egress
// ---------------------------------------------------------------------------
control SwitchEgress(
    inout header_t hdr,
    inout metadata_t eg_md,
    in egress_intrinsic_metadata_t eg_intr_md,
    in egress_intrinsic_metadata_from_parser_t eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) {

    bit<16>       ps_diff;
    INDEX_WIDTH16 htbl_idx;
    HASH_CELL2_T  htbl_ps_update_ret;

    RegisterAction<HASH_CELL1_T, INDEX_WIDTH16, void>(hash_table_flow) update_hash_table_flow = {
        void apply (inout HASH_CELL1_T value) {
            value = hdr.ipv4.src_addr;
        }
    };

    RegisterAction<HASH_CELL2_T, INDEX_WIDTH16, HASH_CELL2_T>(hash_table_ps) update_hash_table_ps = {
        void apply (inout HASH_CELL2_T value, out HASH_CELL2_T ret) {
            if (eg_md.selected_ps > value) {
                ret = value;
                value = eg_md.selected_ps;
            } else {
                ret = 0; // First update will be missing, but we have to use a smaller number or the compilation fails
            }
        }
    };

    action compute_ps_diff() {
        ps_diff = hdr.igeg.ps1 - hdr.igeg.ps2;
    }

    apply {
        if (hdr.igeg.isValid()) {
            if (hdr.igeg.ps1 == 0) {
                hdr.igeg.ps1 = hdr.igeg.ps2;
            } else if (hdr.igeg.ps2 == 0) {
                hdr.igeg.ps2 = hdr.igeg.ps1;
            }
            compute_ps_diff();
            if (ps_diff[15:15] == 1) { // ps1 < ps2, we select the smaller one
                eg_md.selected_ps = hdr.igeg.ps1;
            } else {
                eg_md.selected_ps = hdr.igeg.ps2;
            }
            // Update light part
            htbl_idx = hash_light.get({hdr.ipv4.src_addr},0,HASH_TBL_SIZE); // h_hash(f)
            htbl_ps_update_ret = update_hash_table_ps.execute(htbl_idx);
            if (htbl_ps_update_ret != 0) { // Value changed, update flowID as well
                update_hash_table_flow.execute(htbl_idx);
            }
            // Strip igeg header
            hdr.ethernet.ether_type = hdr.igeg.ether_type;
            hdr.igeg.setInvalid();
        }
    }
}
