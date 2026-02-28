# CGGMP门限签名完整计算流程

## 概述

本文档详细描述了CGGMP门限签名协议的完整计算流程，包括每个阶段的本地计算、广播数据、验证过程和数学公式。

## 总览

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    签名流程总览                                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  离线阶段 (Offline Phase):                                                   │
│  ├── Round 1: 生成随机数、加密、承诺                                          │
│  ├── Round 2: MtA协议、证明                                                   │
│  └── Round 3: 计算中间值、聚合                                                │
│                                                                              │
│  在线阶段 (Online Phase):                                                    │
│  └── 计算签名份额、聚合签名                                                   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 符号说明

| 符号 | 说明 |
|------|------|
| q | 椭圆曲线阶 (secp256k1: 2^256 - 2^32 - 977) |
| G | 椭圆曲线生成元 |
| x | 私钥 |
| X = G × x | 公钥 |
| x_i | 节点i的私钥份额 |
| X_i = G × x_i | 节点i的公钥份额 |
| k | 签名随机数 |
| k_i | 节点i的随机数份额 |
| m | 消息哈希 |
| N | Paillier模数 |
| Ñ | ZKSetup模数 |
| Enc(m) | Paillier加密 |

---

## 一、Round 1 (Presign R1)

### 1.1 本地计算

#### 输入数据

```
• x_i: 私钥份额 (DKG生成)
• X_i = G × x_i: 公钥份额
• Paillier密钥对 (N, p, q)
• ZKSetup参数 (Ñ, s, t)
```

#### 计算过程

```
1. 生成随机数:
   k_i ← Z_q (随机选择)
   gamma_i ← Z_q (随机选择)

2. 计算椭圆曲线点:
   K_i = G × k_i
   Gamma_i = G × gamma_i

3. Paillier加密:
   encK = Enc(k_i) = (1+N)^k_i × r^N mod N²
   encG = Enc(gamma_i) = (1+N)^gamma_i × r'^N mod N²

4. 生成承诺随机数 (Pedersen承诺方案):
   y_i ← Z_q (随机选择，承诺基点的秘密值)
   a_i ← Z_q (随机选择，k_i承诺的随机数)
   b_i ← Z_q (随机选择，gamma_i承诺的随机数)

5. 计算承诺点 (类似Pedersen承诺结构):
   Y_i = G × y_i                           // 承诺基点
   
   // 对k_i的承诺 (嵌入秘密值k_i)
   A1 = G × a_i                            // Pedersen承诺第一部分
   A2 = Y_i × a_i + G × k_i                // Pedersen承诺第二部分，嵌入k_i
        = G × (y_i × a_i + k_i)            // 展开形式
   
   // 对gamma_i的承诺 (嵌入秘密值gamma_i)
   B1 = G × b_i                            // Pedersen承诺第一部分
   B2 = Y_i × b_i + G × gamma_i            // Pedersen承诺第二部分，嵌入gamma_i
        = G × (y_i × b_i + gamma_i)        // 展开形式

6. 生成零知识证明:
   PiEncElgProof(K): 证明encK中的k_i在有效范围内，同时证明知道承诺中的k_i和a_i
   PiEncElgProof(G): 证明encG中的gamma_i在有效范围内，同时证明知道承诺中的gamma_i和b_i
```

#### 承诺方案详解

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Pedersen承诺结构                                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  参数:                                                                       │
│  • G: 椭圆曲线生成元 (公开)                                                  │
│  • Y_i = G × y_i: 承诺基点 (y_i 是秘密，只有节点i知道)                        │
│                                                                              │
│  对k_i的承诺:                                                                │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ Com(k_i) = (A1, A2)                                                   │   │
│  │                                                                     │   │
│  │ A1 = G × a_i                        // 随机掩码部分                   │   │
│  │ A2 = Y_i × a_i + G × k_i            // 嵌入秘密值                     │   │
│  │     = G × (y_i × a_i + k_i)         // 展开形式                       │   │
│  │                                                                     │   │
│  │ 承诺绑定: 知道 a_i 和 y_i 才能打开承诺                                 │   │
│  │ 承诺隐藏: 只看 A1, A2 无法知道 k_i 的值                                │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  对gamma_i的承诺:                                                            │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ Com(gamma_i) = (B1, B2)                                               │   │
│  │                                                                     │   │
│  │ B1 = G × b_i                        // 随机掩码部分                   │   │
│  │ B2 = Y_i × b_i + G × gamma_i        // 嵌入秘密值                     │   │
│  │     = G × (y_i × b_i + gamma_i)     // 展开形式                       │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  安全性质:                                                                   │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ 1. 隐藏性: 只看承诺点无法知道 k_i 或 gamma_i 的值                      │   │
│  │ 2. 绑定性: 一旦广播承诺，无法更改 k_i 或 gamma_i 的值                  │   │
│  │ 3. 零知识性: PiEncElgProof证明知道秘密值，但不泄露                     │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### 承诺随机数的后续使用

```
存储的随机数用于后续轮次的证明:

• y_i → task.presignYScalar    // 用于验证承诺一致性
• a_i → task.presignAScalar    // 用于 Round 3 的 PiLogProof
• b_i → task.presignBScalar    // 用于 Round 2 的 PiLogProof

这些随机数必须保密，泄露会导致秘密值 k_i 和 gamma_i 被推断。
```

### 1.2 广播数据

**消息类型**: `CGGMP_PRESIGN_R1_BROAD`

```json
{
  "encK": "Enc(k_i)",           // Paillier加密的k_i
  "encG": "Enc(gamma_i)",       // Paillier加密的gamma_i
  "Gamma_i": "ECPoint",         // G × gamma_i
  "A1": "ECPoint",              // 承诺点
  "A2": "ECPoint",              // 承诺点
  "B1": "ECPoint",              // 承诺点
  "B2": "ECPoint",              // 承诺点
  "Y_i": "ECPoint",             // 聚合承诺点
  "encElgK": "PiEncElgProof",   // k的范围证明
  "encElgG": "PiEncElgProof"    // gamma的范围证明
}
```

### 1.3 验证过程

#### 验证方程

```
1. 验证PiEncElgProof:
   verify(encElgK) → 证明k_i ∈ [0, q)，同时证明知道承诺中的k_i和a_i
   verify(encElgG) → 证明gamma_i ∈ [0, q)，同时证明知道承诺中的gamma_i和b_i

2. PiEncElgProof验证内容:
   验证加密值与承诺点的一致性:
   • encK 中的 k_i 与 A2 中嵌入的 k_i 是同一个值
   • encG 中的 gamma_i 与 B2 中嵌入的 gamma_i 是同一个值
   • 承诺点 A1, A2, B1, B2, Y_i 的代数关系正确
```

#### 存储数据

```
• peerEncK[j] = encK from node j
• peerEncG[j] = encG from node j
• peerGamma[j] = Gamma_j from node j
• peerY[j] = Y_j from node j
```

---

## 二、Round 2 (Presign R2)

### 2.1 本地计算

#### 输入数据

```
• k_i, gamma_i: 本地随机数
• x_i: 私钥份额
• peerEncK[j]: 其他节点的Enc(k_j)
• peerEncG[j]: 其他节点的Enc(gamma_j)
```

#### 计算过程

**1. MtA-KA协议 (计算 k × gamma)**

```
作为发起方 (对节点j):
  cA = Enc(k_i)
  发送 cA + 范围证明给节点j

作为响应方 (对节点j的请求):
  收到 Enc(k_j) from node j
  生成随机掩码 y
  D_ji = Enc(k_j)^gamma_i × Enc(y) = Enc(k_j × gamma_i + y)
  F_ji = Enc(y)
  beta_ji = -y
  发送 D_ji, F_ji + PiAffGProof 给节点j

收到响应后:
  alpha_ij = Dec(D_ij) = k_i × gamma_j + y
  // beta_ji 来自节点j
```

**2. MtA-X协议 (计算 k × x)**

```
类似MtA-KA，但使用:
  发起方: Enc(k_i)
  响应方: x_j (私钥份额)
  结果: alpha'_ij + beta'_ji = k_i × x_j
```

**3. 计算中间值**

```
delta_i = k_i × gamma_i + Σ_alpha_ij + Σ_beta_ji
chi_i = k_i × x_i + Σ_alpha'_ij + Σ_beta'_ji
```

**4. 生成PiLogProof**

```
证明知道gamma_i使得 Gamma_i = G × gamma_i
```

### 2.2 广播/点对点数据

#### 点对点消息

**消息类型**: `CGGMP_PRESIGN_R2_P2P`

发送给节点j:
```json
{
  "D_ji": "Enc(k_j × gamma_i + y)",    // MtA-KA响应
  "F_ji": "Enc(y)",                    // 掩码加密
  "Dhat_ji": "Enc(k_j × x_i + y')",    // MtA-X响应
  "Fhat_ji": "Enc(y')",                // 掩码加密
  "affGProof": "PiAffGProof",          // 仿射变换证明
  "affGProofX": "PiAffGProof"          // MtA-X的仿射变换证明
}
```

#### 广播消息

**消息类型**: `CGGMP_PRESIGN_R2_BROAD`

```json
{
  "logProof": "PiLogProof",    // 离散对数证明
  "Y_i_r2": "ECPoint",         // R2承诺点
  "B1_r2": "ECPoint",          // R2承诺点
  "B2_r2": "ECPoint"           // R2承诺点
}
```

### 2.3 验证过程

#### 验证方程

```
1. 验证PiAffGProof:
   验证 D = C^x × Enc(y) 的正确性
   其中 C = Enc(k_j), x = gamma_i, y = 掩码

2. 验证PiLogProof:
   验证证明者知道gamma_j使得 Gamma_j = G × gamma_j
   Schnorr验证: g^z = A × Y^e mod p
```

---

## 三、Round 3 (Presign R3)

### 3.1 本地计算

#### 输入数据

```
• k_i, gamma_i: 本地随机数
• delta_i, chi_i: Round 2计算的中间值
• peerGamma[j]: 其他节点的Gamma_j
• X = G × x: 聚合公钥
```

#### 计算过程

```
1. 计算聚合Gamma:
   Gamma = Σ Gamma_j = G × Σ gamma_j = G × gamma

2. 计算椭圆曲线点:
   Delta_i = Gamma × k_i
   S_i = Gamma × chi_i

3. 生成PiLogProof:
   证明知道k_i使得 Delta_i = Gamma × k_i
```

### 3.2 广播数据

**消息类型**: `CGGMP_PRESIGN_R3_BROAD`

```json
{
  "delta_i": "BigInteger",     // k_i × gamma_i 的份额
  "Delta_i": "ECPoint",        // Gamma × k_i
  "S_i": "ECPoint",            // Gamma × chi_i
  "logProof": "PiLogProof"     // 离散对数证明
}
```

### 3.3 验证过程

#### 验证方程

```
1. 验证PiLogProof:
   验证证明者知道k_j使得 Delta_j = Gamma × k_j

2. 验证点一致性:
   收集所有delta_i后: delta = Σ delta_i
   验证: G × delta = Σ Delta_i
```

### 3.4 finalizePresign计算

```
1. delta = Σ delta_i
2. deltaInv = delta⁻¹ mod q
3. kTilde = k_i × deltaInv mod q
4. chiTilde = chi_i × deltaInv mod q
5. S̃_j = S_j × deltaInv (对每个节点j)

Presignature = {Gamma, kTilde, chiTilde}
```

---

## 四、Online Phase

### 4.1 本地计算

#### 输入数据

```
• m: 消息哈希
• Presignature: {Gamma, kTilde, chiTilde}
• S̃_j: 每个节点的验证点
```

#### 计算过程

```
1. 计算 r:
   r = Gamma.x mod q  (Gamma点的x坐标)
   
   注意: Gamma = G × gamma，而不是 G × k⁻¹
   这与标准ECDSA不同，但最终签名仍然有效（见下方数学推导）

2. 计算签名份额:
   e = m mod q
   
   sigma_i = kTilde × e + r × chiTilde mod q
           = (k_i × delta⁻¹) × m + r × (chi_i × delta⁻¹) mod q
           = delta⁻¹ × (k_i × m + r × chi_i) mod q

3. 数学推导 (验证与ECDSA的一致性):
   
   标准ECDSA签名公式:
   ┌──────────────────────────────────────────────────────────────────────┐
   │ R = k × G,  r = R.x                                                  │
   │ s = k⁻¹ × (m + r × x) mod q                                          │
    │                                                                      │
    │ 验证: s⁻¹ × m × G + s⁻¹ × r × X = R                                  │
   └──────────────────────────────────────────────────────────────────────┘
   
   CGGMP签名计算:
   ┌──────────────────────────────────────────────────────────────────────┐
   │ Gamma = G × gamma,  r = Gamma.x                                      │
   │                                                                      │
   │ 聚合签名份额:                                                         │
   │ s = Σ sigma_i                                                        │
    │   = Σ[delta⁻¹ × (k_i × m + r × chi_i)]                              │
    │   = delta⁻¹ × (m × Σk_i + r × Σchi_i)                               │
    │   = delta⁻¹ × (m × k + r × k × x)                                   │
    │   = (k × gamma)⁻¹ × k × (m + r × x)                                 │
    │   = gamma⁻¹ × (m + r × x)                                           │
   └──────────────────────────────────────────────────────────────────────┘
   
   验证CGGMP签名是有效的ECDSA签名:
   ┌──────────────────────────────────────────────────────────────────────┐
    │ u1 = s⁻¹ × m = gamma × (m + r × x)⁻¹ × m                            │
    │ u2 = s⁻¹ × r = gamma × (m + r × x)⁻¹ × r                            │
    │                                                                      │
    │ R' = u1 × G + u2 × X                                                │
    │    = gamma × (m + r × x)⁻¹ × m × G + gamma × (m + r × x)⁻¹ × r × x × G │
    │    = gamma × (m + r × x)⁻¹ × (m + r × x) × G                        │
    │    = gamma × G                                                      │
    │    = Gamma                                                          │
    │                                                                      │
    │ R'.x = Gamma.x = r ✓                                                │
   └──────────────────────────────────────────────────────────────────────┘
   
   结论: CGGMP签名(r, s)是有效的ECDSA签名，只是随机数表示方式不同:
   • 标准ECDSA: 使用k，R = k × G
   • CGGMP: 使用gamma，Gamma = G × gamma
   • 两者都满足ECDSA验证方程
```

### 4.2 发送数据

**消息类型**: `CGGMP_SIGN_S_SHARE`

发送内容 (非发起方发送给发起方):
```json
{
  "sigma_i": "BigInteger"   // 签名份额 s_i
}
```

### 4.3 验证过程

#### 验证方程

```
对每个签名份额 sigma_j:

  验证: Gamma × sigma_j = DeltaTilde_j × m + STilde_j × r

其中:
  • Gamma = G × gamma (聚合的Gamma点)
  • DeltaTilde_j = Delta_j × delta⁻¹
  • STilde_j = S_j × delta⁻¹
  • m = 消息哈希
  • r = Gamma.x mod q

验证方程推导:
  左边 = Gamma × sigma_j
       = G × gamma × delta⁻¹ × (k_j × m + r × chi_j)
       = G × gamma × delta⁻¹ × k_j × m + G × gamma × delta⁻¹ × chi_j × r
  
  右边 = DeltaTilde_j × m + STilde_j × r
       = (Delta_j × delta⁻¹) × m + (S_j × delta⁻¹) × r
       = (Gamma × k_j × delta⁻¹) × m + (Gamma × chi_j × delta⁻¹) × r
       = Gamma × k_j × delta⁻¹ × m + Gamma × chi_j × delta⁻¹ × r
       = G × gamma × k_j × delta⁻¹ × m + G × gamma × chi_j × delta⁻¹ × r
  
  左边 = 右边 ✓

代码实现:
  left = Gamma × sigma_j
  right = DeltaTilde_j × m + STilde_j × r
  验证: left == right
```

#### 聚合签名

```
s = Σ sigma_i mod q

最终签名: (r, s)

验证完整签名 (标准ECDSA验证):
  u1 = s⁻¹ × m mod q
  u2 = s⁻¹ × r mod q
  R' = u1 × G + u2 × X
  验证: R'.x mod q = r

代码实现:
  s = sumShares(sShares, curveOrder)
  // 规范化: 如果s > q/2，则s = q - s
  if (s > curveOrder/2) {
      s = curveOrder - s
  }
  // DER编码签名
  signature = DER_encode(r, s)
  // 验证签名
  verified = verifySignature(publicKey, messageHash, r, s)
```

---

## 五、完整数据流总结

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    完整数据流                                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Round 1:                                                                    │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ 计算: k_i, gamma_i, K_i, Gamma_i, encK, encG, 承诺, PiEncElgProof     │   │
│  │ 广播: encK, encG, Gamma_i, 承诺, PiEncElgProof                         │   │
│  │ 验证: PiEncElgProof, 承诺一致性                                         │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  Round 2:                                                                    │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ 计算: MtA-KA, MtA-X, delta_i, chi_i, PiAffGProof, PiLogProof           │   │
│  │ P2P: D_ji, F_ji, Dhat_ji, Fhat_ji, PiAffGProof                         │   │
│  │ 广播: PiLogProof, 承诺                                                 │   │
│  │ 验证: PiAffGProof, PiLogProof                                          │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  Round 3:                                                                    │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ 计算: Gamma, Delta_i, S_i, PiLogProof                                  │   │
│  │ 广播: delta_i, Delta_i, S_i, PiLogProof                                │   │
│  │ 验证: PiLogProof, G × delta = Σ Delta_i                                │   │
│  │ 输出: Presignature = {Gamma, kTilde, chiTilde}, S̃_i                   │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  Online:                                                                     │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ 计算: r, sigma_i                                                       │   │
│  │ 发送: sigma_i (给发起方)                                               │   │
│  │ 验证: G × sigma_j = S̃_j                                               │   │
│  │ 输出: 签名 (r, s)                                                      │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 六、零知识证明汇总

| 阶段 | 证明类型 | 证明目标 | 验证方程 |
|------|---------|---------|---------|
| R1 | PiEncElgProof | 加密值范围 | k_i, gamma_i ∈ [0, q) |
| R2 | PiAffGProof | MtA仿射变换 | D = C^x × Enc(y) |
| R2 | PiLogProof | 离散对数知识 | Gamma_i = G × gamma_i |
| R3 | PiLogProof | 离散对数知识 | Delta_i = Gamma × k_i |

---

## 七、关键数学公式

### ECDSA签名

```
签名生成:
  R = k⁻¹ × G mod q
  r = R.x mod q
  s = k⁻¹ × (m + r × x) mod q

签名验证:
  u1 = s⁻¹ × m mod q
  u2 = s⁻¹ × r mod q
  R' = u1 × G + u2 × X
  验证: R'.x = r
```

### Paillier同态性质

```
加法同态:
  Enc(m1) × Enc(m2) = Enc(m1 + m)

标量乘法:
  Enc(m)^k = Enc(k × m)
```

### MtA协议

```
目标: α + β = a × b

发起方:
  cA = Enc(a)
  发送 cA 给响应方

响应方:
  cB = cA^b × Enc(y) = Enc(a × b + y)
  β = -y
  发送 cB 给发起方

发起方:
  α = Dec(cB) = a × b + y

结果: α + β = a × b + y + (-y) = a × b
```

---

## 八、安全性要点

1. **随机数保护**: k_i 和 gamma_i 必须是真正的随机数，且每次签名都不同
2. **范围证明**: 所有加密值必须在有效范围内，防止溢出攻击
3. **零知识证明**: 每一步都有对应的证明，确保协议正确执行
4. **可识别中止**: 如果有人作弊，可以被识别并投诉
5. **前向安全**: 即使部分私钥份额泄露，历史签名仍然安全
