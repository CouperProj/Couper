// Bitmap(LC)
// index width = 32
// table count = 2, table size = 0.5M / 2 = 2^18, cell width = 2byte, total size = 1.0MB
#define BM_TBL_SIZE       262144
#define BM_CELL_WIDTH     16

// Hyper Log Log
// index width = 32
// table count = 2, estimator count = 2^12, register cnt = 2^6, cell width = 1byte, total size = 0.5MB
#define HLL_TBL_SIZE      4096  // 4096 estimators per table
#define HLL_EST_SIZE      64    // 64 registers per estimator
#define HLL_CELL_WIDTH    8     // 8 bits per register, store the cnt of leading 0s
#define HLL_SUM_WIDTH     16    // Partial Sum

// f: hdr.ipv4.src_addr
// e: hdr.ipv4.dst_addr

typedef bit<BM_CELL_WIDTH>   BM_CELL_T;
typedef bit<HLL_CELL_WIDTH>  HLL_CELL_T;
typedef bit<16>              HLL_SUM_T;

// ---------------------------------------------------------------------------
// Extern definition
// ---------------------------------------------------------------------------
Register<BM_CELL_T, INDEX_WIDTH32>(BM_TBL_SIZE) bitmap_LC_table_1;
Register<BM_CELL_T, INDEX_WIDTH32>(BM_TBL_SIZE) bitmap_LC_table_2;
Hash<bit<32>>(HashAlgorithm_t.RANDOM) hash_bitmap_f_32_1;
Hash<bit<32>>(HashAlgorithm_t.RANDOM) hash_bitmap_f_32_2;
Hash<bit<8>>(HashAlgorithm_t.CRC8) hash_bitmap_fe_8;

Register<HLL_CELL_T, INDEX_WIDTH32>(HLL_TBL_SIZE * HLL_EST_SIZE) hll_table_1;
Register<HLL_CELL_T, INDEX_WIDTH32>(HLL_TBL_SIZE * HLL_EST_SIZE) hll_table_2;
Register<HLL_SUM_T, INDEX_WIDTH32>(HLL_TBL_SIZE) hll_sum_table_1;
Register<HLL_SUM_T, INDEX_WIDTH32>(HLL_TBL_SIZE) hll_sum_table_2;
// Hash<bit<32>>(HashAlgorithm_t.RANDOM) hash_hll_f_32_1;
// Hash<bit<32>>(HashAlgorithm_t.RANDOM) hash_hll_f_32_2;
Hash<bit<8>>(HashAlgorithm_t.CRC8) hash_hll_fe_8;
Hash<bit<32>>(HashAlgorithm_t.CRC32) hash_hll_fe_32;
Hash<bit<32>>(HashAlgorithm_t.IDENTITY) hash_hll_id_32_1;
Hash<bit<32>>(HashAlgorithm_t.IDENTITY) hash_hll_id_32_2;

// ---------------------------------------------------------------------------
// Ingress
// ---------------------------------------------------------------------------
control SwitchIngress(
        inout header_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

    // ---------------------------------------------------------------------------[Forward]

    action hit(PortId_t port) {
        ig_intr_tm_md.ucast_egress_port = port;
    }

    action miss() {
        ig_intr_dprsr_md.drop_ctl = 0x1; // Drop packet.
    }

    table forward {
        key = {
            hdr.ethernet.dst_addr : exact;
        }

        actions = {
            hit;
            miss;
        }

        const default_action = hit(OUTPUT_PORT); // Forward every packet to OUTPUT_PORT
        size = 1024;
    }

    // ---------------------------------------------------------------------------[Variables]
    bit<8>              bitmap_mask_index = 0;
    bit<16>             bitmap_mask = 16w0;
    bit<BM_CELL_WIDTH>  bitmap_tbl1_value = 16w0;
    bit<BM_CELL_WIDTH>  bitmap_check_ret = 16w0;

    bit<32>             hll_rand = 0;
    bit<8>              hll_val = 0;        // Range: 1-33
    bit<8>              hll_reg_index = 0;  // Range: 0-63
    INDEX_WIDTH32       hll_tbl_idx1;       // Range: 0-4095
    INDEX_WIDTH32       hll_tbl_idx2;       // Range: 0-4095
    bit<HLL_CELL_WIDTH> hll_update_ret1;    // Range: 0-32, 127
    bit<HLL_CELL_WIDTH> hll_update_ret2;    // Range: 0-32, 127
    INDEX_WIDTH32       hll_sum_index_tmp1; // Range: 0-4095
    INDEX_WIDTH32       hll_sum_index_tmp2; // Range: 0-4095
    INDEX_WIDTH32       hll_sum_index1;     // Range: 0-4095
    INDEX_WIDTH32       hll_sum_index2;     // Range: 0-4095
    bit<HLL_SUM_WIDTH>  hll_sum_delta1;     // Range: 1-33
    bit<HLL_SUM_WIDTH>  hll_sum_delta2;     // Range: 1-33
    bit<HLL_SUM_WIDTH>  hll_ps2;            // Range: 0-33*64=2112

    // ---------------------------------------------------------------------------[Bitmap Actions]

    RegisterAction<BM_CELL_T, INDEX_WIDTH32, BM_CELL_T>(bitmap_LC_table_1) read_bitmap_LC_table_1 = { // Read bitmap table 1
        void apply (inout BM_CELL_T value, out BM_CELL_T ret) {
            ret = value;
        }
    };

    RegisterAction<BM_CELL_T, INDEX_WIDTH32, BM_CELL_T>(bitmap_LC_table_2) read_bitmap_LC_table_2 = { // Read bitmap table 1, output result of bitwise AND
        void apply (inout BM_CELL_T value, out BM_CELL_T ret) {
            ret = value & bitmap_tbl1_value;
        }
    };

    RegisterAction<BM_CELL_T, INDEX_WIDTH32, void>(bitmap_LC_table_1) update_bitmap_LC_table_1 = { // Perform LC update on bitmap table 1
        void apply (inout BM_CELL_T value) {
            value = value | bitmap_mask;
        }
    };

    RegisterAction<BM_CELL_T, INDEX_WIDTH32, void>(bitmap_LC_table_2) update_bitmap_LC_table_2 = { // Perform LC update on bitmap table 2
        void apply (inout BM_CELL_T value) {
            value = value | bitmap_mask;
        }
    };

    // ---------------------------------------------------------------------------[HLL Actions]

    RegisterAction<HLL_CELL_T, INDEX_WIDTH32, HLL_CELL_T>(hll_table_1) update_hll_table_1 = {
        void apply (inout HLL_CELL_T value, out HLL_CELL_T ret) {
            if (hll_val > value) {
                ret = value;
                value = hll_val;
            } else {
                ret = 0; // First update will be missing, but we have to do this
            }
        }
    };
    
    RegisterAction<HLL_CELL_T, INDEX_WIDTH32, HLL_CELL_T>(hll_table_2) update_hll_table_2 = {
        void apply (inout HLL_CELL_T value, out HLL_CELL_T ret) {
            if (hll_val > value) {
                ret = value;
                value = hll_val;
            } else {
                ret = 0; // First update will be missing, but we have to do this
            }
        }
    };

    RegisterAction<HLL_SUM_T, INDEX_WIDTH32, HLL_SUM_T>(hll_sum_table_1) update_hll_sum_table_1 = {
        void apply (inout HLL_SUM_T value, out HLL_SUM_T ret) {
            value = value + hll_sum_delta1;
            ret = value;
        }
    };
    
    RegisterAction<HLL_SUM_T, INDEX_WIDTH32, HLL_SUM_T>(hll_sum_table_2) update_hll_sum_table_2 = {
        void apply (inout HLL_SUM_T value, out HLL_SUM_T ret) {
            value = value + hll_sum_delta2;
            ret = value;
        }
    };

    // ---------------------------------------------------------------------------

    action read_bitmap_1() {
        ig_md.resubmit_data.bm_tbl1_index = hash_bitmap_f_32_1.get({hdr.ipv4.src_addr},0,BM_TBL_SIZE); // h_1(f), valid bits [17:0]
        bitmap_tbl1_value = read_bitmap_LC_table_1.execute(ig_md.resubmit_data.bm_tbl1_index); // Read bitmap table 1
    }

    action write_bitmap_1() {
        update_bitmap_LC_table_1.execute(ig_md.resubmit_data.bm_tbl1_index);
    }

    table bitmap_op_1 {
        key = {
            ig_intr_md.resubmit_flag : exact;
        }
        actions = {
            read_bitmap_1;
            write_bitmap_1;
        }
        size = 2;
    }

    action read_bitmap_2() {
        ig_md.resubmit_data.bm_tbl2_index = hash_bitmap_f_32_2.get({hdr.ipv4.src_addr},0,BM_TBL_SIZE); // h_1(f), valid bits [17:0]
        bitmap_check_ret = read_bitmap_LC_table_2.execute(ig_md.resubmit_data.bm_tbl2_index); // Read bitmap table 2, output result of bitwise AND
    }

    action write_bitmap_2() {
        update_bitmap_LC_table_2.execute(ig_md.resubmit_data.bm_tbl2_index);
    }

    table bitmap_op_2 {
        key = {
            ig_intr_md.resubmit_flag : exact;
        }
        actions = {
            read_bitmap_2;
            write_bitmap_2;
        }
        size = 2;
    }

    // ---------------------------------------------------------------------------

    action hll_ps_action_1() {
        hll_sum_delta1 = (bit<16>)(hll_val - hll_update_ret1);
        hll_sum_index_tmp1 = hll_tbl_idx1 >> 6; // Original valid bits are [31:0], becomes [25:0] after >> 6
        hll_sum_index1 = hash_hll_id_32_1.get(hll_sum_index_tmp1);
        hdr.igeg.setValid();
        hdr.igeg.ps1 = update_hll_sum_table_1.execute(hll_sum_index1);
        hdr.igeg.ether_type = hdr.ethernet.ether_type;
        hdr.ethernet.ether_type = ETHERTYPE_IGEG;
    }

    table hll_ps_op_1 {
        key = {
            hll_update_ret1 : exact;  // If the value is 0, then the action is NoAction
        }
        actions = {
            hll_ps_action_1;
            NoAction;
        }
        default_action = NoAction();
        size = 1;
    }

    action hll_ps_action_2() {
        hll_sum_delta2 = (bit<16>)(hll_val - hll_update_ret2);
        hll_sum_index_tmp2 = hll_tbl_idx2 >> 6; // Original valid bits are [31:0], becomes [25:0] after >> 6
        hll_sum_index2 = hash_hll_id_32_2.get(hll_sum_index_tmp2);
        hdr.igeg.setValid();
        hdr.igeg.ps2 = update_hll_sum_table_2.execute(hll_sum_index2);
        hdr.igeg.ether_type = hdr.ethernet.ether_type;
        hdr.ethernet.ether_type = ETHERTYPE_IGEG;
    }

    table hll_ps_op_2 {
        key = {
            hll_update_ret2 : exact; // If the value is 0, then the action is NoAction
        }
        actions = {
            hll_ps_action_2;
            NoAction;
        }
        default_action = NoAction();
        size = 1;
    }

    // ---------------------------------------------------------------------------

    action set_resubmit_flag(bit<3> resubmit_type) {
        ig_intr_dprsr_md.resubmit_type = resubmit_type;
    }

    table bitmap_full_lookup {
        key = {
            bitmap_check_ret: exact;
        }

        actions = {
            set_resubmit_flag;
        }

        size = 560; // C_{16}^{3} = 560 full conditions

        default_action = set_resubmit_flag(3w1); // Resubmit and update if bitmap is not full
    }

    // ---------------------------------------------------------------------------

    action write_bitmap_mask(bit<16> mask) { // PHV.bitmap_mask_index -> PHV.bitmap_mask
        bitmap_mask = mask;
    }

    table mask_lookup {
        key = {
            bitmap_mask_index: exact;
        }

        actions = {
            write_bitmap_mask;
            NoAction;
        }

        size = 16;

        default_action = NoAction();
    }
    
    // ---------------------------------------------------------------------------
    
    action write_leading_zero(bit<8> cnt) { // PHV.hll_rand -> PHV.hll_val
        hll_val = cnt;
    }

    table leading_zero_lookup {
        key = {
            hll_rand : lpm;
        }

        actions = {
            write_leading_zero;
            NoAction;
        }
        
        size = 33;

        default_action = NoAction();
    }

    // ---------------------------------------------------------------------------

    apply {
        bitmap_mask_index = hash_bitmap_fe_8.get({hdr.ipv4.src_addr, hdr.ipv4.dst_addr},0,16); // bitmap_mask_index = h_bm(f,e)
        mask_lookup.apply(); // bitmap_mask = (1 << bitmap_mask_index);
        bitmap_op_1.apply(); // For new packet: read bitmap table 1; for resubmitted packet: write bitmap table 1
        bitmap_op_2.apply(); // For new packet: read bitmap table 2; for resubmitted packet: write bitmap table 2

        if (ig_intr_md.resubmit_flag == 0) { // New packet, AND result of 2 bitmaps already stored in bitmap_check_ret
            bitmap_full_lookup.apply(); // ig_intr_dprsr_md.resubmit_type = bitmap_full_lookup(bitmap_check_ret)
            if (ig_intr_dprsr_md.resubmit_type == 3w0) { // No resubmission, bitmap is full, update HLL and hash table
                hll_rand = hash_hll_fe_32.get({hdr.ipv4.src_addr, hdr.ipv4.dst_addr});
                hll_val = 0;
                leading_zero_lookup.apply(); // Use table lookup to calc hll_val
                hll_reg_index = hash_hll_fe_8.get({hdr.ipv4.src_addr, hdr.ipv4.dst_addr},0,HLL_EST_SIZE); // h_hll_1(f,e), used to locate reg

                hll_tbl_idx1 = ig_md.resubmit_data.bm_tbl1_index[31:6] ++ hll_reg_index[5:0]; // [31:6] from bm_tbl1_index, [5:0] from hll_reg_index
                hll_update_ret1 = update_hll_table_1.execute(hll_tbl_idx1);
                hll_tbl_idx2 = ig_md.resubmit_data.bm_tbl2_index[31:6] ++ hll_reg_index[5:0]; // [31:6] from bm_tbl2_index, [5:0] from hll_reg_index
                hll_update_ret2 = update_hll_table_2.execute(hll_tbl_idx2);

                hll_ps_op_1.apply(); // If hll_table_1 is updated (hll_update_ret1 != 0), then update hll_sum_table_1, and set igeg header
                hll_ps_op_2.apply(); // If hll_table_2 is updated (hll_update_ret2 != 0), then update hll_sum_table_2, and set igeg header

                // If hdr.igeg is valid, at least one of the two selected HLLs has its partial sum updated, but we don't know which one (or both)
                // Due to the limitation of stage count, we defer the selection of partial sum to the egress pipeline
            }
        }
        forward.apply();
    }
}