# AVE 断言表达式差分 —— 27.0.1 缺哪些校验（决定性清单）

> 方法：AVE 把完整断言表达式编进 `__cstring`（`%s:%d %s | <msg>` 后面紧跟源码条件）。
> 正则抓 `pInfo->` 且含比较运算符的串，两版本对比。
> 结果：27.0.1 **51** 条 → 27.2 **65** 条，**新增 17 条**，消失 3 条。

## 27.2 新增的 17 条（= 27.0.1 缺失的校验）

| # | 断言表达式 | 形态 |
|---|---|---|
| 1 | `0 <= pInfo->uPropCfg.sHEVC.iNumberOfTemporalLayers && ... <= 7` | **属性上界，已证可达** |
| 2 | `0 <= ...sAlgCfg.sGOP.iNumOfTemporalLayer && ... <= 7` | 会话配置上界 |
| 3 | `0 < ...sAlgCfg.sGOP.iNumOfTemporalLayer && ... <= 7` | 同上（下界变体） |
| 4 | `pInfo->sHEVC_VPS.vps_max_sub_layers_minus1 < 7 && vps_num_layer_sets_minus1 < 16 && vps_num_hrd_parameters <= 16 && ...` | **VPS 数组边界** |
| 5 | `pInfo->saHEVC_SPS[i].sps_max_sub_layers_minus1 < 7 && num_long_term_ref_pics_sps <= 16` | **SPS 数组边界** |
| 6 | `pInfo->saHEVC_PPS[i].num_tile_columns_minus1 <= 256 && num_tile_rows_minus1 <= 256 && chroma_qp_offset_list_len_minus1 <= 5` | **PPS 数组边界** |
| 7 | `pInfo->sHEVC_RPS.strps.num_short_term_ref_pic_sets < 65 && (num_long_term_sps + num_long_term_pics) <= 16` | **RPS 数组边界** |
| 8 | `pInfo->saHEVC_SPS[i].log2_max_pic_order_cnt_lsb_minus4 <= 12` | 位宽上界 |
| 9 | `2 <= pInfo->VideoParamsDriver.userDPBnumFrames && ... <= 17` | **DPB 数组** |
| 10 | `4 <= pInfo->sSyntaxCfgAVC.iLog2MaxFrameNum && ... <= 16 && 4 <= ...iLog2MaxPOCLsb && ...` | AVC 位宽 |
| 11 | `pInfo->sSyntaxCfgAVC.iNumSliceGroups == 1 && 1 <= iNumRefIdxL0DefaultActive && ... <= 16 && ...` | AVC 引用计数 |
| 12 | `pInfo->sSyntaxCfgAVC.iBitDepthLuma == 8 && pInfo->sSyntaxCfgAVC.iBitDepthChroma == 8` | 位深限制 |
| 13 | `pInfo->uPropCfg.sHEVC.iMCTFStrengthLevelNum >= 0 && ... <= 2` | MCTF 属性 |
| 14 | `pInfo->uPropCfg.sAV1.iMCTFStrengthLevelNum >= 0 && ... <= 2` | MCTF 属性（AV1） |
| 15 | `pInfo->uPropCfg.sMCTF.iMCTFStrengthLevelNum >= 0 && ... <= 2` | MCTF 属性（通用） |
| 16 | `pInfo->sBufPFSet.saMBStats[m].iAddr != 0` | 缓冲区非空 |
| 17 | `pInfo->sHEVC_VPS.num_add_layer_sets <= 64` | VPS 数组 |

## 关键结构：同一个补丁同时补「属性上界」和「结构数组上界」

```
uPropCfg.sHEVC.iNumberOfTemporalLayers <= 7     （属性，用户直接可控）
        ↕  同一条补丁
sHEVC_VPS.vps_max_sub_layers_minus1 < 7          （结构里的 8 项数组边界）
saHEVC_SPS[i].sps_max_sub_layers_minus1 < 7      （同上）
sAlgCfg.sGOP.iNumOfTemporalLayer <= 7            （会话配置）
```

**`7` 出现 4 次 ⇒ 目标是一组 8 项的数组/位域。**

**推断链（待证）**：
```
app 设 NumberOfTemporalLayers = 65535
  -> 存进 uPropCfg.sHEVC.iNumberOfTemporalLayers（27.0.1 无上界，实测通过）
  -> 编码器据此生成 VPS/SPS，vps_max_sub_layers_minus1 等字段被带上大值
  -> 驱动按该字段索引 8 项数组 -> 越界
=> 27.2 在同一路径上把两处都补了
```

**这解释了此前「设 65535 无崩溃」**：单设属性不触发，需要让编码器**真的去构造子层结构**
（开 temporal scalability / 多层编码 / 每帧指定 temporalLayerId）。

## 下一步实验（唯一）

1. `NumberOfTemporalLayers = 65535`（远超 7）
2. 打开 temporal scalability（构造子层 GOP）
3. 每帧通过 attachment 指定 `temporalLayerId`，逼编码器按该维度分配/索引
4. 反向组合：`NumberOfTemporalLayers = 2` + `temporalLayerId = 255`
5. 全抓 `kernel{AppleAVE2}` 日志（免 KDK 符号预言机），出现新的 AVERR 行即命中新检查

**判据**：新 panic / 新 AVERR 行 / 编码器 hang，任一即是进展。

## 附

- 原始清单：`out/AVE-ASSERTIONS.txt`（65 条）
- 可达性实证：`out/AVE-REACH.md`
- 27.2 检查函数定位：`out/AVE2-PATCH-LOCATED.md`
