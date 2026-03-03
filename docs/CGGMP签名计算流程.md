# CGGMP门限签名完整计算流程

## 概述

本文档详细描述了CGGMP门限签名协议的完整计算流程，包括每个阶段的本地计算、广播数据、验证过程和数学公式。本文档基于实际代码实现编写。

## 总览

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    签名流程总览                                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  离线阶段 (Offline Phase):                                                   │
│  ├── Round 1: 生成随机数、加密、承诺、广播Paillier公钥和ZKSetup              │
│  ├── R1-Echo: 可选的承诺确认机制                                             │
│  ├── Round 2: MtA协议(P2P)、生成PiAffGProof、广播PiLogProof                 │
│  ├── Round 3: 计算delta_i/chi_i、聚合Gamma、广播PiLogProof                   │
│  └── finalizePresign: 验证并生成Presignature                                │
│                                                                              │
│  在线阶段 (Online Phase):                                                    │
│  ├── Gamma-Commit: 广播Gamma承诺                                             │
│  ├── Gamma-Open: 打开Gamma承诺                                               │
│  ├── 计算签名份额sigma_i                                                     │
│  └── 聚合签名、验证、生成最终签名                                             │
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
| Ñ | ZKSetup模数 |
| Enc(m) | Paillier加密 |

---

## 一、Round 1 (Presign R1)

### 1.1 本地计算

#### 输入数据

```
• x_i: 私钥份额 (DKG生成)
• X_i = G × x_i: 公钥份额
• Paillier密钥对 (N, p, q)
• ZKSetup参数 (Ñ, h1, h2)
```

#### 计算过程

```java
// 代码实现: CggmpSignatureOfflineHandler.java runOfflinePhase()

1. 生成随机数:
   k_i ← Z_q (随机选择，非零)
   gamma_i ← Z_q (随机选择，非零)

2. 计算椭圆曲线点:
   Gamma_i = G × gamma_i

3. 生成承诺随机数:
   y_i ← Z_q (随机选择，承诺基点)
   a_i ← Z_q (随机选择，k_i承诺的随机数)
   b_i ← Z_q (随机选择，gamma_i承诺的随机数)

4. 计算承诺点:
   Y_i = G × y_i                                    // 承诺基点
   A1 = G × a_i                                     // Pedersen承诺第一部分
   A2 = Y_i × a_i + G × k_i = G × (y_i × a_i + k_i) // 嵌入k_i
   B1 = G × b_i                                     // Pedersen承诺第一部分
   B2 = Y_i × b_i + G × gamma_i = G × (y_i × b_i + gamma_i) // 嵌入gamma_i

5. Paillier加密 (使用随机数r):
   encK = task.paillier.encryptWithRandomness(k_i)
   encG = task.paillier.encryptWithRandomness(gamma_i)
   K = encK.c()   // 加密值
   G = encG.c()   // 加密值
   r_K = encK.r() // 随机数
   r_G = encG.r() // 随机数

6. 生成零知识证明:
   PiEncElgProof(K): 使用参数(A1, Y_i, A2, k_i, r_K, a_i, y_i)
   PiEncElgProof(G): 使用参数(B1, Y_i, B2, gamma_i, r_G, b_i, y_i)

   证明内容:
   - k_i, gamma_i ∈ [0, q) 范围证明
   - 加密值与承诺点的一致性证明

7. 本地验证 (发送前):
   验证本地生成的PiEncElgProof是否正确
   如果验证失败，记录错误信息但继续广播（允许其他节点投诉）
```

#### 存储数据

```java
task.k_i = k_i;
task.presignGamma.put(svc.nodeId, Gamma_i);
task.presignYScalar = y_i;      // 存储用于后续验证
task.presignAScalar = a_i;
task.presignBScalar = b_i;
task.presignY.put(svc.nodeId, Y_i);
task.presignA1.put(svc.nodeId, A1);
task.presignA2.put(svc.nodeId, A2);
task.presignB1.put(svc.nodeId, B1);
task.presignB2.put(svc.nodeId, B2);
task.presignK.put(svc.nodeId, K);
task.presignG.put(svc.nodeId, G);
```

### 1.2 广播数据

**消息类型**: `CGGMP_PRESIGN_R1_BROAD`

```json
{
  "signatureTaskId": "task-uuid",
  "senderId": 1,
  "K": "hex-encoded",           // Paillier加密的k_i
  "G": "hex-encoded",           // Paillier加密的gamma_i
  "Y": "hex-encoded-ecpoint",   // G × y_i
  "A1": "hex-encoded-ecpoint",  // 承诺点
  "A2": "hex-encoded-ecpoint",  // 承诺点
  "B1": "hex-encoded-ecpoint",  // 承诺点
  "B2": "hex-encoded-ecpoint", // 承诺点
  "encElgProofK": {             // PiEncElgProof (k_i)
    "S": "hex", "T": "hex", "D": "hex",
    "Y": "hex-ecpoint", "Z": "hex-ecpoint",
    "z1": "hex", "z2": "hex", "z3": "hex", "w": "hex"
  },
  "encElgProofG": { ... },      // PiEncElgProof (gamma_i)
  "paillierPublicKey": {        // Paillier公钥
    "n": "hex", "nsquare": "hex", "g": "hex", "bitLength": 2048
  },
  "zkSetup": {                  // ZKSetup参数
    "hatN": "hex", "h1": "hex", "h2": "hex"
  },
  "auxParams": { ... }          // 辅助参数
}
```

### 1.3 验证过程

```java
// 代码: CggmpSignatureMessageHandler.handleCggmpSignPresignR1()

1. 接收并存储所有节点的R1数据:
   peerPaillierKeys.put(senderId, paillierPublicKey);
   peerZkSetups.put(senderId, zkSetup);
   presignK.put(senderId, K);
   presignG.put(senderId, G);
   presignGamma.put(senderId, Gamma_i);
   presignY.put(senderId, Y_i);
   presignA1.put(senderId, A1);
   presignA2.put(senderId, A2);
   presignB1.put(senderId, B1);
   presignB2.put(senderId, B2);

2. 验证PiEncElgProof:
   verifyEncElgProof(encElgProofK, pk, zk, G, A1, Y_i, A2, K)
   verifyEncElgProof(encElgProofG, pk, zk, G, B1, Y_i, B2, G)

3. 记录验证结果 (允许继续流程，即使验证失败):
   // 验证失败会记录日志，但不会立即中止
   // 后续可以通过投诉机制处理
```

### 1.4 R1-Echo (可选确认)

```java
// 如果启用 presignEchoEnabled

1. 计算R1数据的哈希:
   hash = SHA256(JsonUtils.toJson(r1Data))

2. 广播R1-Echo:
   {
     "signatureTaskId": "task-uuid",
     "senderId": 1,
     "hash": "sha256-hash"
   }

3. 等待所有节点的Echo，确认共识
```

---

## 二、Round 2 (Presign R2)

### 2.1 本地计算

#### 输入数据

```
• k_i, gamma_i: 本地随机数
• x_i: 私钥份额 (乘以拉格朗日系数lambda_i)
• peerPaillierKeys: 其他节点的Paillier公钥
• peerPresignK: 其他节点的Enc(k_j)
• Gamma_i = G × gamma_i
```

#### 计算过程

```java
// 代码: CggmpSignatureOfflineHandler runOfflinePhase() -> R2部分

1. 计算本地私钥份额:
   x_i_raw = loadLocalShare(groupPublicKey)
   lambda_i = computeSignatureLagrange(task, nodeId, curveOrder)
   x_i = x_i_raw.multiply(lambda_i).mod(curveOrder)

2. 对每个其他节点j执行MtA协议:
   // MtA-KA: 计算 k_i × gamma_j (通过j的Paillier公钥)
   for (peerId : participants) {
     if (peerId == nodeId) continue;

     pk_j = peerPaillierKeys.get(peerId);
     K_j = peerPresignK.get(peerId);

     // 生成随机掩码
     beta = randomNonZero(curveOrder)
     betaHat = randomNonZero(curveOrder)

     // 计算 D_ji = Enc(k_j)^gamma_i × Enc(beta) = Enc(k_j × gamma_i + beta)
     // 代码: pk_j.multiply(K_peer, ctx.gamma_i()).multiply(encNegBeta.c())
     D_ji = pk_j.multiply(K_j, gamma_i).multiply(encNegBeta.c()).mod(n^2)

     // 计算 F_ji = Enc(beta) 用于后续解密
     F_ji = encrypt(beta)

     // MtA-X: 计算 k_j × x_i
     Dhat_ji = pk_j.multiply(K_j, x_i).multiply(encNegBetaHat.c()).mod(n^2)
     Fhat_ji = encrypt(betaHat)

     // 生成PiAffGProof证明
     proof = createAffGProofNegY(G, Gamma_i, pk_j.n, our_n, K_j, D_ji, F_ji, gamma_i, beta, ...)
     proofHat = createAffGProofNegY(G, X_i, pk_j.n, our_n, K_j, Dhat_ji, Fhat_ji, x_i, betaHat, ...)
   }
```

#### MtA协议详解

```
目标: 节点i和节点j共同计算 a × b = alpha + beta

发起方(i, 持有k_i):
  cA = Enc(k_i)
  发送 cA 给响应方j

响应方(j, 持有a_j):
  生成随机掩码 beta
  cB = cA^a_j × Enc(beta) = Enc(k_i × a_j + beta)
  发送 cB 给发起方i

发起方i:
  alpha = Dec(cB) = k_i × a_j + beta
  (响应方j持有beta)

结果: alpha + beta = k_i × a_j ✓
```

### 2.2 广播数据

#### P2P消息

直接发送给对应节点:

```json
{
  "targetId": 2,
  "signatureTaskId": "task-uuid",
  "D_ji": "hex-encoded",
  "F_ji": "hex-encoded",
  "Dhat_ji": "hex-encoded",
  "Fhat_ji": "hex-encoded",
  "affGProof": { "A": [...], "B": [...], ... },
  "affGProofHat": { ... }
}
```

#### 广播消息

**消息类型**: `CGGMP_PRESIGN_R2_BROAD`

```json
{
  "signatureTaskId": "task-uuid",
  "senderId": 1,
  "Gamma": "hex-encoded-ecpoint",    // G × gamma_i
  "D": { "2": "hex", "3": "hex", ... },   // D_ji map
  "Dhat": { "2": "hex", "3": "hex", ... },
  "F": { "2": "hex", "3": "hex", ... },
  "Fhat": { "2": "hex", "3": "hex", ... },
  "affGProofs": { "2": {...}, "3": {...}, ... },
  "affGProofsHat": { ... },
  "logProof": { "U1": "...", "U2": "...", "z1": "...", "z2": "..." },
  "X": "hex-encoded-ecpoint"  // G × x_i × lambda_i
}
```

### 2.3 验证过程

```java
// 代码: handleCggmpSignPresignR2()

1. 接收并解密:
   for (peerId : peerIds) {
     // 从peerId接收P2P消息，包含D_ij, F_ij等
     // 使用本地Paillier私钥解密
     alpha = decrypt(D_ij)
     alphaHat = decrypt(Dhat_ij)

     // 存储beta (来自发送方广播的F_ij)
     // 注意: beta = -y，其中y是响应方生成的掩码
   }

2. 验证PiAffGProof:
   verifyAffGProof(proof, G, Gamma_i, pk.n, K_peer, D_ji, F_ji)
   verifyAffGProof(proofHat, G, X_i, pk.n, K_peer, Dhat_ji, Fhat_ji)

3. 验证PiLogProof:
   // 证明Gamma_i = G × gamma_i
   verifyLogProof(logProof, G, G, Gamma_i, Y_i, B1, B2)
```

---

## 三、Round 3 (Presign R3)

### 3.1 本地计算

```java
// 代码: continuePresignAfterR2()

1. 收集所有节点的D和beta，计算中间值:
   delta_i = k_i × gamma_i
   chi_i = x_i × k_i

   for (peerId : peerIds) {
     D_ij = task.presignD.get(peerId)
     Dhat_ij = task.presignDhat.get(peerId)
     beta = task.presignBeta.get(peerId)
     betaHat = task.presignBetaHat.get(peerId)

     // 解密MtA结果
     alpha = decrypt(D_ij)
     alphaHat = decrypt(Dhat_ij)

     // 累加
     delta_i += alpha + beta
     chi_i += alphaHat + betaHat
   }
   delta_i = delta_i mod q
   chi_i = chi_i mod q

2. 计算椭圆曲线点:
   Gamma = sum(peerPresignGamma)  // 聚合Gamma
   Delta_i = Gamma × k_i
   S_i = Gamma × chi_i

3. 生成PiLogProof:
   // 证明Delta_i = Gamma × k_i
   logProofR3 = createLogProof(G, Gamma, Delta_i, Y_i, A1, A2, k_i, a_i)
```

### 3.2 广播数据

**消息类型**: `CGGMP_PRESIGN_R3_BROAD`

```json
{
  "signatureTaskId": "task-uuid",
  "senderId": 1,
  "delta": "hex-encoded",           // k_i × gamma_i + sum(alpha + beta)
  "Delta": "hex-encoded-ecpoint",  // Gamma × k_i
  "S": "hex-encoded-ecpoint",      // Gamma × chi_i
  "logProof": { "U1": "...", "U2": "...", "z1": "...", "z2": "..." }
}
```

### 3.3 验证过程

```java
// 代码: finalizePresign()

1. 聚合delta:
   delta = sum(peerDeltas)

2. 验证delta:
   left = G × delta
   right = sum(Delta_i)
   if (left != right) {
     // 验证失败，广播投诉
     evidence = buildDecEvidenceDelta(task, gamma_i, delta_i)
     broadcastComplaint("Presign delta verification failed", evidence)
     return
   }

3. 验证S点:
   leftS = X × delta
   rightS = sum(S_i)
   if (leftS != rightS) {
     // 验证失败，识别作恶节点
     identifyMaliciousPeer(...)
     return
   }

4. 计算Presignature:
   deltaInv = delta^(-1) mod q
   kTilde = k_i × deltaInv mod q
   chiTilde = chi_i × deltaInv mod q
   S̃_i = S_i × deltaInv

5. 存储Presignature:
   task.presignature = Presignature(Gamma, kTilde, chiTilde)
   task.presignDeltaTilde.put(nodeId, Delta_i × deltaInv)
   task.presignSTilde.put(nodeId, S_i × deltaInv)
```

---

## 四、Online Phase

### 4.1 阶段1: Gamma-Commit (可选)

```java
// 代码: handleCggmpSignGammaCommit()

1. 计算Gamma_commit:
   commit = hash(messageHash || Gamma || "GAMMA-COMMIT")

2. 生成EcChaumPedersenProof:
   证明知道gamma使得 Gamma = G × gamma

3. 广播:
   {
     "taskId": "...",
     "senderId": 1,
     "commit": "hex-ecpoint",
     "proofA": "hex-ecpoint",
     "proofR": "hex",
     "proofS": "hex"
   }
```

### 4.2 阶段2: 计算签名份额

```java
// 代码: runOnlinePhase()

1. 获取Presignature:
   Gamma = presignature.Gamma()
   kTilde = presignature.kTilde()
   chiTilde = presignature.chiTilde()

2. 计算r:
   r = Gamma.x mod q
   if (r == 0) restart

3. 处理HD钱包偏移 (可选):
   if (hdEnabled) {
     shift = HMAC(chainCode, messageHash) mod q
     chiTilde = chiTilde + kTilde × shift
   }

4. 计算消息哈希e:
   e = Hash(message) mod q

5. 计算签名份额:
   sigma_i = kTilde × e + r × chiTilde mod q

6. 本地验证份额:
   if (!verifySigmaShare(task, nodeId, sigma_i)) {
     fail("Local signature share verification failed")
   }

7. 广播sigma_i:
   发送给签名发起方
```

### 4.3 签名份额验证

```java
// 代码: verifySigmaShare()

验证方程:
  Gamma × sigma_i = DeltaTilde_i × e + STilde_i × r

其中:
  DeltaTilde_i = Delta_i × delta^(-1)
  STilde_i = S_i × delta^(-1)

验证:
  left = Gamma.multiply(sigma_i)
  right = DeltaTilde.multiply(e).add(sTilde.multiply(r))
  return left.equals(right.normalize())
```

### 4.4 最终签名聚合

```java
// 代码: finalizeSignatureAsInitiator()

1. 收集所有sigma_i:
   sShares.put(senderId, sigma_i)

2. 验证所有份额:
   offenders = []
   for (peerId : participants) {
     if (!verifySigmaShare(task, peerId, sShares.get(peerId))) {
       offenders.add(peerId)
     }
   }
   if (!offenders.isEmpty()) {
     broadcastComplaint("Invalid signature share", ...)
     return
   }

3. 聚合签名:
   s = sum(sShares) mod q

4. 规范化s (防止R=0签名):
   if (s > q/2) {
     s = q - s
   }

5. DER编码:
   der = DER_encode(r, s)

6. 最终验证:
   verified = verifySignature(publicKey, messageHash, r, s, domain)

7. 输出:
   signature = Base64(der)
```

---

## 五、完整数据流图

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    CGGMP签名完整数据流                                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ Round 1 (Offline):                                                     │   │
│  │                                                                        │   │
│  │  Local: k_i, gamma_i, Gamma_i, encK, encG, commitments, proofs       │   │
│  │  ─────────────────────────────────────────────────────────────────── │   │
│  │  Broadcast: CGGMP_PRESIGN_R1                                          │   │
│  │    ├── encK, encG (Paillier加密)                                       │   │
│  │    ├── Gamma_i, Y_i, A1, A2, B1, B2 (椭圆曲线点)                       │   │
│  │    ├── PiEncElgProof (k), PiEncElgProof (gamma)                       │   │
│  │    ├── Paillier公钥, ZKSetup                                          │   │
│  │    └── auxParams                                                       │   │
│  │                                                                        │   │
│  │  Echo (optional): CGGMP_PRESIGN_R1_ECHO (SHA256 hash)                │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                    ↓                                         │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ Round 2 (Offline):                                                     │   │
│  │                                                                        │   │
│  │  Local: MtA-KA, MtA-X, alpha, alphaHat, beta, betaHat                │   │
│  │  ─────────────────────────────────────────────────────────────────── │   │
│  │  P2P (to each peer): CGGMP_PRESIGN_R2_P2P                            │   │
│  │    ├── D_ji, F_ji (MtA-KA响应)                                        │   │
│  │    ├── Dhat_ji, Fhat_ji (MtA-X响应)                                  │   │
│  │    ├── PiAffGProof, PiAffGProofHat                                   │   │
│  │                                                                        │   │
│  │  Broadcast: CGGMP_PRESIGN_R2                                          │   │
│  │    ├── Gamma_i, X_i                                                   │   │
│  │    ├── D, Dhat, F, Fhat (map per peer)                                │   │
│  │    ├── affGProofs, affGProofsHat (per peer)                          │   │
│  │    └── PiLogProof                                                     │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                    ↓                                         │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ Round 3 (Offline):                                                     │   │
│  │                                                                        │   │
│  │  Local: delta_i, chi_i, Delta_i, S_i                                  │   │
│  │  ─────────────────────────────────────────────────────────────────── │   │
│  │  Broadcast: CGGMP_PRESIGN_R3                                          │   │
│  │    ├── delta_i                                                         │   │
│  │    ├── Delta_i = Gamma × k_i                                         │   │
│  │    ├── S_i = Gamma × chi_i                                            │   │
│  │    └── PiLogProof                                                     │   │
│  │                                                                        │   │
│  │  finalizePresign:                                                      │   │
│  │    ├── verify G×delta = ΣDelta_i                                      │   │
│  │    ├── verify X×delta = ΣS_i                                          │   │
│  │    └── output: Presignature = (Gamma, kTilde, chiTilde)              │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                    ↓                                         │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ Online Phase:                                                          │   │
│  │                                                                        │   │
│  │  1. Gamma-Commit (optional):                                           │   │
│  │     Broadcast: Gamma_commit + EcChaumPedersenProof                   │   │
│  │                                                                        │   │
│  │  2. Gamma-Open:                                                        │   │
│  │     Broadcast: Gamma (打开承诺)                                        │   │
│  │                                                                        │   │
│  │  3. Compute sigma:                                                     │   │
│  │     r = Gamma.x mod q                                                 │   │
│  │     sigma_i = kTilde×e + r×chiTilde                                    │   │
│  │                                                                        │   │
│  │  4. Send to initiator: CGGMP_SIGN_S_SHARE                            │   │
│  │     { signatureTaskId, senderId, sigma_i }                            │   │
│  │                                                                        │   │
│  │  5. Finalize:                                                         │   │
│  │     ├── verify each sigma_i                                           │   │
│  │     ├── s = Σsigma_i                                                  │   │
│  │     ├── normalize s (s > q/2 ? q-s : s)                              │   │
│  │     ├── DER encode                                                     │   │
│  │     └── output: (r, s) signature                                       │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 六、零知识证明汇总

| 阶段 | 证明类型 | 证明目标 | 验证方程 |
|------|---------|---------|---------|
| R1 | PiEncElgProof(K) | 加密值k_i范围 + 承诺一致性 | 验证k_i ∈ [0, q) |
| R1 | PiEncElgProof(G) | 加密值gamma_i范围 + 承诺一致性 | 验证gamma_i ∈ [0, q) |
| R2 | PiAffGProof | MtA仿射变换 D = C^x × Enc(y) | 验证 D·F^(-e) = A·Y^e |
| R2 | PiLogProof | 离散对数 Gamma_i = G × gamma_i | Schnorr验证 |
| R3 | PiLogProof | 离散对数 Delta_i = Gamma × k_i | Schnorr验证 |
| Online | EcChaumPedersenProof | Gamma承诺 | 验证知道gamma |

---

## 七、安全性要点

1. **随机数保护**: k_i 和 gamma_i 必须是真正的随机数，且每次签名都不同
2. **范围证明**: 所有加密值必须在有效范围内，防止溢出攻击
3. **零知识证明**: 每一步都有对应的证明，确保协议正确执行
4. **可识别中止**: 如果有人作弊，可以被识别并投诉
5. **前向安全**: 即使部分私钥份额泄露，历史签名仍然安全
6. **HD钱包支持**: 通过chaincode派生偏移量，增强密钥安全性
7. **双重验证**: Presignature生成时验证delta和S，签名时验证sigma_i

---

## 八、附录: 消息类型

| 消息类型 | 方向 | 说明 |
|---------|------|------|
| CGGMP_SIGN_OFFLINE_INIT | Broadcast | 初始化离线阶段 |
| CGGMP_PRESIGN_R1 | Broadcast | Round 1数据 |
| CGGMP_PRESIGN_R1_ECHO | Broadcast | R1确认 |
| CGGMP_PRESIGN_R2 | Broadcast | Round 2数据 |
| CGGMP_PRESIGN_R2_P2P | P2P | MtA响应 |
| CGGMP_PRESIGN_R3 | Broadcast | Round 3数据 |
| CGGMP_SIGN_ONLINE_INIT | Broadcast | 初始化在线阶段 |
| CGGMP_SIGN_GAMMA_COMMIT | Broadcast | Gamma承诺 |
| CGGMP_SIGN_GAMMA_OPEN | Broadcast | 打开Gamma |
| CGGMP_SIGN_S_SHARE | P2P | 签名份额 |
| CGGMP_SIGN_COMPLAINT | Broadcast | 投诉 |
