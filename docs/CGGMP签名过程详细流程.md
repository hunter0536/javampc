# CGGMP签名过程详细流程

## 目录

1. [整体架构](#一整体架构)
2. [预签名阶段](#二预签名阶段)
3. [在线签名阶段](#三在线签名阶段)
4. [完整流程图](#四完整流程图)
5. [数学验证](#五数学验证)
6. [MtA协议使用总结](#六mta协议使用总结)
7. [关键变量对照表](#七关键变量对照表)

---

## 一、整体架构

```
┌─────────────────────────────────────────────────────────────────┐
│                    CGGMP签名两阶段架构                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  阶段一: 预签名                                          │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ 输入: 私钥分片 x_i, Paillier密钥                          │   │
│  │ 输出: 预签名 (Gamma, kTilde, chiTilde)                   │   │
│  │ 特点: 可离线执行，可批量预生成                             │   │
│  └─────────────────────────────────────────────────────────┘   │
│                           ↓                                     │
│  阶段二: 在线签名                                         │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ 输入: 预签名, 消息哈希 z                                   │   │
│  │ 输出: ECDSA签名                                  │   │
│  │ 特点: 仅需1轮交互，延迟极低                                │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 二、预签名阶段

### 目标

计算预签名数据，为后续在线签名做准备：

```
输出:
- Gamma = gamma × G  (椭圆曲线点)
- kTilde = k × delta^(-1)  (k的变形)
- chiTilde = chi × delta^(-1)  (chi的变形)
```

---

### Round 1: 生成随机数并加密

```
┌─────────────────────────────────────────────────────────────────┐
│                    预签名 Round 1                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  每个参与方 i 执行:                                              │
│                                                                 │
│  1. 生成随机数:                                                  │
│     k_i ← Z_q          (随机数k的分片)                           │
│     gamma_i ← Z_q      (随机数gamma的分片)                       │
│                                                                 │
│  2. 计算椭圆曲线点:                                              │
│     Gamma_i = gamma_i × G                                       │
│                                                                 │
│  3. Paillier加密:                                               │
│     K_i = E_i(k_i)      (加密k_i)                               │
│     G_i = E_i(gamma_i)  (加密gamma_i)                           │
│                                                                 │
│  4. 生成零知识证明:                                              │
│     Π_enc(k_i): 证明K_i是正确加密的                              │
│     Π_enc(gamma_i): 证明G_i是正确加密的                          │
│                                                                 │
│  5. 广播: (K_i, G_i, Gamma_i, 证明)                             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**代码实现**：

```java
// 生成随机数
task.k_i = randomNonZero(curveOrder);
BigInteger gamma_i = randomNonZero(curveOrder);

// 计算椭圆曲线点
task.presignGamma.put(nodeId, Secp256k1Curve.multiply(G, gamma_i));

// Paillier加密
PaillierEncryption.Encryption encK = task.paillier.encryptWithRandomness(task.k_i);
PaillierEncryption.Encryption encG = task.paillier.encryptWithRandomness(gamma_i);

// 生成零知识证明
PiEncElgProof encElgK = PresignProofs.createEncElgProof(...);
PiEncElgProof encElgG = PresignProofs.createEncElgProof(...);
```

---

### Round 2: MtA协议计算交叉项

```
┌─────────────────────────────────────────────────────────────────┐
│                    预签名 Round 2                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  目标: 计算交叉项                                                │
│    - k_i × gamma_j (用于计算 delta = k × gamma)                 │
│    - k_i × x_j     (用于计算 chi = k × x)                       │
│                                                                 │
│  对于每对参与方, i ≠ j:                                   │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ MtA协议 1: 计算 k_i × gamma_j                           │   │
│  │                                                         │   │
│  │ Party i (Initiator):                                    │   │
│  │   - 秘密: k_i                                           │   │
│  │   - 发送: E_i(k_i)                                      │   │
│  │                                                         │   │
│  │ Party j (Responder):                                    │   │
│  │   - 秘密: gamma_j                                       │   │
│  │   - 计算: D_ji = E_i(k_i)^gamma_j × E_i(r)              │   │
│  │   - 得到: beta_ji (满足 alpha_ij + beta_ji = k_i×gamma_j)│   │
│  │                                                         │   │
│  │ Party i 解密:                                           │   │
│  │   - alpha_ij = D_i(D_ji) = k_i×gamma_j + r              │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ MtA协议 2: 计算 k_i × x_j                               │   │
│  │                                                         │   │
│  │ 同理，使用 k_i 和 x_j                                    │   │
│  │ 得到: alpha'_ij + beta'_ji = k_i × x_j                  │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  广播: D_ij, Dhat_ij (加密的交叉项)                             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**代码实现**：

```java
// 计算 delta_i = k_i × gamma_i (本地项)
BigInteger delta_i = gamma_i.multiply(task.k_i).mod(curveOrder);

// 计算 chi_i = k_i × x_i (本地项)
BigInteger chi_i = x_i.multiply(task.k_i).mod(curveOrder);

// MtA协议计算交叉项
for (int peerId : task.participants) {
    if (peerId == nodeId) continue;
    
    // MtA for k_i × gamma_j
    MtAProtocol mtaGamma = new MtAProtocol(paillier, curveOrder);
    // ... 执行MtA协议 ...
    
    // MtA for k_i × x_j
    MtAProtocol mtaX = new MtAProtocol(paillier, curveOrder);
    // ... 执行MtA协议 ...
}
```

---

### Round 3: 聚合并生成预签名

```
┌─────────────────────────────────────────────────────────────────┐
│                    预签名 Round 3                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. 计算 delta = k × gamma:                                     │
│                                                                 │
│     delta_i = k_i × gamma_i                     (本地项)        │
│     delta = Σ delta_i + Σ alpha_ij + Σ beta_ji  (聚合)          │
│                                                                 │
│  2. 计算 chi = k × x:                                           │
│                                                                 │
│     chi_i = k_i × x_i                           (本地项)        │
│     chi = Σ chi_i + Σ alpha'_ij + Σ beta'_ji    (聚合)          │
│                                                                 │
│  3. 计算 delta^(-1):                                            │
│                                                                 │
│     deltaInv = delta^(-1) mod q                                 │
│                                                                 │
│  4. 计算 Gamma = gamma × G:                                     │
│                                                                 │
│     Gamma = Σ Gamma_i = (gamma_1 + gamma_2 + ...) × G           │
│                                                                 │
│  5. 计算预签名值:                                                │
│                                                                 │
│     kTilde = k × deltaInv                                       │
│            = k × (k × gamma)^(-1)                               │
│            = gamma^(-1)                                         │
│                                                                 │
│     chiTilde = chi × deltaInv                                   │
│              = (k × x) × (k × gamma)^(-1)                       │
│              = x × gamma^(-1)                                   │
│                                                                 │
│  6. 输出预签名:                                                  │
│                                                                 │
│     预签名 = (Gamma, kTilde, chiTilde)                          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**代码实现**：

```java
// 聚合 delta
BigInteger delta = delta_i;
for (BigInteger alpha : task.deltaAlphas.values()) {
    delta = delta.add(alpha);
}
for (BigInteger beta : task.deltaBetas.values()) {
    delta = delta.add(beta);
}

// 聚合 chi
BigInteger chi = chi_i;
for (BigInteger alpha : task.chiAlphas.values()) {
    chi = chi.add(alpha);
}
for (BigInteger beta : task.chiBetas.values()) {
    chi = chi.add(beta);
}

// 计算 delta^(-1)
BigInteger deltaInv = delta.modInverse(curveOrder);

// 计算 Gamma
ECPoint GammaFinal = r3ctx.Gamma.normalize();

// 计算预签名值
BigInteger kTilde = task.k_i.multiply(deltaInv).mod(curveOrder);
BigInteger chiTilde = chi.multiply(deltaInv).mod(curveOrder);

// 保存预签名
task.presignature = new Presignature(GammaFinal, kTilde, chiTilde);
```

---

### 预签名数学验证

```
验证 R = k^(-1) × G:

R = delta^(-1) × Gamma
  = (k × gamma)^(-1) × (gamma × G)
  = gamma^(-1) × k^(-1) × gamma × G
  = k^(-1) × G  ✓
```

---

## 三、在线签名阶段

### 目标

使用预签名和消息哈希，计算最终签名：

```
输入:
- 预签名 (Gamma, kTilde, chiTilde)
- 消息哈希 z

输出:
- ECDSA签名
```

---

### 在线签名流程

```
┌─────────────────────────────────────────────────────────────────┐
│                    在线签名阶段                                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. 计算 R点:                                                   │
│                                                                 │
│     R = delta^(-1) × Gamma = k^(-1) × G                         │
│     r = R.x mod n                                               │
│                                                                 │
│  2. 计算签名分量 s:                                              │
│                                                                 │
│     标准公式: s = k^(-1) × (z + r×d)                            │
│                                                                 │
│     门限分解:                                                    │
│       s = k^(-1) × z + r × k^(-1) × d                           │
│         = kInv × z + r × kInv × d                               │
│                                                                 │
│     其中:                                                        │
│       kInv = kTilde × delta  (从预签名恢复)                      │
│       d = x_1 + x_2 + ... + x_n                                 │
│                                                                 │
│  3. 通过MtA计算 kInv_i × x_j:                                    │
│                                                                 │
│     对于每对, i ≠ j:                                     │
│       - Party i: 秘密 kInv_i                                    │
│       - Party j: 秘密 x_j                                       │
│       - MtA结果: alpha_ij + beta_ji = kInv_i × x_j              │
│                                                                 │
│  4. 计算各方的 s_i:                                              │
│                                                                 │
│     t_i = kInv_i × z + r × kInv_i × x_i   (本地项)              │
│     s_i = t_i + Σ alpha_ij + Σ beta_ji                          │
│                                                                 │
│  5. 聚合签名:                                                    │
│                                                                 │
│     s = Σ s_i mod n                                             │
│       = kInv × z + r × kInv × d                                 │
│       = k^(-1) × (z + r×d)                                      │
│                                                                 │
│  6. 输出最终签名:                                                │
│                                                                 │
│     签名 = (r, s)                                               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**代码实现**：

```java
// 计算 R 和 r
ECPoint R = presignature.Gamma.multiply(deltaInv).normalize();
BigInteger r = R.getAffineXCoord().toBigInteger().mod(curveOrder);

// 计算 kInv_i = kTilde_i × delta
BigInteger kInv_i = presignature.kTilde.multiply(delta).mod(curveOrder);

// 本地项
BigInteger t_i = kInv_i.multiply(messageHash)
    .add(r.multiply(kInv_i).multiply(x_i))
    .mod(curveOrder);

// MtA计算交叉项 kInv_i × x_j
for (int participantId : task.participants) {
    if (participantId == nodeId) continue;
    
    MtAProtocol protocol = new MtAProtocol(paillier, curveOrder);
    MtAInitiatorMessage initiatorMessage = protocol.generateInitiatorMessage(
        kInv_i, task.zkSetup, mtaContext
    );
    // ... 执行MtA协议 ...
}

// 计算签名分量 s_i
private BigInteger computeSShare(Gg20SignatureTask task, BigInteger mod) {
    BigInteger s = task.kInv_i.multiply(task.t_i).mod(mod);
    
    for (BigInteger alpha : task.stAlphas.values()) {
        s = s.add(alpha);
    }
    for (BigInteger beta : task.stBetas.values()) {
        s = s.add(beta);
    }
    
    return s.mod(mod);
}

// 聚合签名
BigInteger s = BigInteger.ZERO;
for (BigInteger sShare : task.sShares.values()) {
    s = s.add(sShare);
}
s = s.mod(curveOrder);
```

---

## 四、完整流程图

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         CGGMP门限签名完整流程                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        预签名阶段                          │   │
│  ├─────────────────────────────────────────────────────────────────────┤   │
│  │                                                                     │   │
│  │  Round 1:                                                           │   │
│  │  ┌─────────────────────────────────────────────────────────────┐   │   │
│  │  │ 生成: k_i, gamma_i                                           │   │   │
│  │  │ 加密: K_i = E(k_i), G_i = E(gamma_i)                         │   │   │
│  │  │ 广播: (K_i, G_i, Gamma_i, 证明)                              │   │   │
│  │  └─────────────────────────────────────────────────────────────┘   │   │
│  │                              ↓                                      │   │
│  │  Round 2:                                                           │   │
│  │  ┌─────────────────────────────────────────────────────────────┐   │   │
│  │  │ MtA: 计算 k_i × gamma_j → alpha_ij, beta_ji                  │   │   │
│  │  │ MtA: 计算 k_i × x_j → alpha'_ij, beta'_ji                    │   │   │
│  │  │ 广播: D_ij, Dhat_ij                                          │   │   │
│  │  └─────────────────────────────────────────────────────────────┘   │   │
│  │                              ↓                                      │   │
│  │  Round 3:                                                           │   │
│  │  ┌─────────────────────────────────────────────────────────────┐   │   │
│  │  │ 聚合: delta = k × gamma, chi = k × x                         │   │   │
│  │  │ 计算: deltaInv = delta^(-1)                                  │   │   │
│  │  │ 输出: 预签名 (Gamma, kTilde, chiTilde)                       │   │   │
│  │  └─────────────────────────────────────────────────────────────┘   │   │
│  │                                                                     │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                              ↓                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        在线签名阶段                         │   │
│  ├─────────────────────────────────────────────────────────────────────┤   │
│  │                                                                     │   │
│  │  输入: 预签名 + 消息哈希 z                                           │   │
│  │                              ↓                                      │   │
│  │  ┌─────────────────────────────────────────────────────────────┐   │   │
│  │  │ 计算: R = delta^(-1) × Gamma, r = R.x                        │   │   │
│  │  │ 计算: kInv_i = kTilde × delta                                │   │   │
│  │  │ MtA: 计算 kInv_i × x_j → alpha''_ij, beta''_ji               │   │   │
│  │  │ 计算: s_i = kInv_i×z + r×kInv_i×x_i + Σ(alpha) + Σ(beta)     │   │   │
│  │  │ 聚合: s = Σ s_i                                              │   │   │
│  │  │ 输出: 签名                                │   │   │
│  │  └─────────────────────────────────────────────────────────────┘   │   │
│  │                                                                     │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 五、数学验证

### 验证R点正确性

```
R = delta^(-1) × Gamma
  = (k × gamma)^(-1) × (gamma × G)
  = gamma^(-1) × k^(-1) × gamma × G
  = k^(-1) × G  ✓
```

### 验证签名正确性

```
s = Σ s_i
  = Σ [kInv_i × z + r × kInv_i × x_i + Σ(alpha) + Σ(beta)]

展开交叉项:
  Σ_i Σ_j (alpha_ij + beta_ji) = Σ_i Σ_j kInv_i × x_j
                                = kInv × d

所以:
  s = kInv × z + r × kInv × d
    = kInv × (z + r × d)
    = k^(-1) × (z + r × d)  ✓
```

---

## 六、MtA协议使用总结

| 阶段 | MtA计算 | 目的 |
|-----|--------|------|
| **预签名 Round 2** | k_i × gamma_j | 计算 delta = k × gamma |
| **预签名 Round 2** | k_i × x_j | 计算 chi = k × x |
| **在线签名** | kInv_i × x_j | 计算签名分量 s |

---

## 七、关键变量对照表

| 变量 | 含义 | 出现阶段 |
|-----|------|---------|
| k_i | 随机数k的分片 | 预签名 |
| gamma_i | 随机数gamma的分片 | 预签名 |
| x_i | 私钥分片 | DKG生成 |
| delta | k × gamma | 预签名 |
| chi | k × x | 预签名 |
| Gamma | gamma × G | 预签名 |
| kTilde | k × delta^(-1) | 预签名输出 |
| chiTilde | chi × delta^(-1) | 预签名输出 |
| kInv_i | k^(-1)的分片 | 在线签名 |
| r | R点的x坐标 | 在线签名 |
| s_i | 签名分片 | 在线签名 |

---

## 八、ECDSA签名公式回顾

### 标准ECDSA签名

```
签名生成:
1. 选择随机数 k ∈ [1, n-1]
2. 计算 R = k^(-1) × G
3. 计算 r = R.x mod n
4. 计算 s = k^(-1) × (z + r × d) mod n
5. 输出签名

其中:
- d: 私钥
- z: 消息哈希
- n: 椭圆曲线阶
```

### 门限ECDSA签名

```
签名生成:
1. 预签名阶段: 计算 R = k^(-1) × G (不暴露k)
2. 在线阶段: 计算 s = k^(-1) × (z + r × d) (不暴露d)

关键挑战:
- k = k_1 + k_2 + ... + k_n (分片)
- d = x_1 + x_2 + ... + x_n (分片)
- 需要在不暴露分片的情况下计算 k^(-1) 和 k^(-1) × d
```

---

## 参考资料

1. [CGGMP21论文](https://eprint.iacr.org/2021/060.pdf) - UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts
2. [GG18论文](https://eprint.iacr.org/2019/114.pdf) - Fast Multiparty Threshold ECDSA with Fast Trustless Setup
3. [GG20论文](https://eprint.iacr.org/2020/540.pdf) - One Round Threshold ECDSA with Identifiable Abort
