# AVE 27.2 新增校验（从二进制字符串直接提取）

## 泄露出来的函数名

- `AVE_Client_CheckLRMEInfo`
- `AVE_Client_CheckMCTFInfo`
- `AVE_HEVC_CheckVPSExtBounds`

## 新增的边界检查语义

- AV1 MCTF strength count out of range %d %d [0 %d]
- AVC PPS count is out of range %d %d %d %d
- AVC bit depth is not supported %d %d %d
- AVC log2_max is out of range %d %d %d (max %d)
- HEVC MCTF strength count out of range %d %d [0 %d]
- HEVC PPS count is out of range %d %d %d %d %d %d
- HEVC RPS count is out of range %d %d %d %d
- HEVC SPS count is out of range %d %d %d %d %d
- HEVC VPS count is out of range %d %d %d %d %d %d
- HEVC VPS extension layer/OLS counts are out of range %d
- HEVC VPS highest_layer_idx_plus1 sum is out of range %d %d %d %d
- HEVC VPS layer-set total is out of range %d %d %d %d
- HEVC VPS layer_id_in_nuh is out of range %d %d %d %d
- HEVC VPS num_add_layer_sets is out of range %d %d %d
- HEVC VPS output-layer-set total is out of range %d %d %d %d %d
- HEVC VPS vps_max_layers_minus1 is out of range %d %d %d
- HEVC log2_max_pic_order_cnt_lsb_minus4 is out of range %d %d %d (max %d)
- LRME info is not correct %p %lld %d
- MCTF info is not correct %p %lld %d
- MCTF strength count out of range %p %lld %d [0 %d]
- number of sub layer is out of range %d %d %d
- number of temporal layers (prop) is out of range %d %d %d
- %d [%d %d]

## 其它

- source and destination alias %p %d %p
- too many parameter sets %d %d %d %p %d
- too many parameter sets %p %d %d %d %p %d
