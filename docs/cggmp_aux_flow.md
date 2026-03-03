# CGGMP AUX（辅助信息）生成流程

## 概述

AUX（辅助信息）是 CGGMP 签名协议中用于 Paillier 同态加密的关键数据。AUX 包含了每个节点的 Paillier 公钥和 Pedersen 承诺参数，是签名协议的前置条件。

## 总览

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         AUX 协议流程总览                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  触发方式:                                                                   │
│  ├── 自动触发: Leader 节点定期检查，缺失时自动发起                            │
│  └── 手动触发: 调用 createAuxTask() + startAuxProcess(taskId)               │
│                                                                              │
│  协议轮次 (4轮):                                                             │
│  ├── Round 1: 承诺阶段 - 广播 V_commit (RBC)                                │
│  ├── R1-Echo: 确认阶段 - 广播 Echo 哈希 (RBC)                              │
│  ├── Round 2: 揭示阶段 - 广播 Paillier公钥 + Pedersen参数                   │
│  └── Round 3: 证明阶段 - 广播 MOD证明 + FAC证明                             │
│                                                                              │
│  输出:                                                                       │
│  └── 每个节点的 AUX: Paillier密钥 + ZKSetup参数                              │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 一、协议参与方与角色

| 角色 | 说明 |
|------|------|
| **Initiator** | 发起方，通常是任务发起节点 |
| **Participant** | 参与方，所有参与协议的节点 |
| **Leader** | 协调者，负责触发自动 AUX 检查 |

---

## 二、Round 1 - 承诺阶段

### 2.1 本地计算

```java
// 代码: CggmpAuxProtocolHandler.runAuxProtocolAsync()

1. 生成 Paillier 密钥对:
   paillier = new PaillierEncryption(auxPaillierBits)  // 默认 3072 bits
   // 生成 p, q (大素数)
   // n = p × q, g = n + 1

2. 生成 Pedersen 参数 (ZKSetup):
   ped = ZKSetup.generateWithLambda(paillier.bitLength)
   // hatN = n² (Paillier 模数的平方)
   // h1, h2 (Pedersen 承诺基点)
   // lambda (用于生成 h1, h2)

3. 生成随机数:
   rho_i = randomBytes(32)   // 用于承诺
   u_i = randomBytes(32)      // 用于承诺

4. 生成 PRM 证明:
   // 证明 Pedersen 参数由正确的 lambda 生成
   prmProof = RefreshProofs.createPrmProof(
       hatN, s, t, pedersenLambda,
       ctx = buildAuxContext(taskId, executionId, nodeId, "PRM")
   )

5. 本地验证 PRM 证明 (发送前):
   selfOk = RefreshProofs.verifyPrmProof(prmProof, hatN, s, t, prmCtx)
```

### 2.2 承诺计算

```java
// 计算 V_commit (用于承诺所有数据)
V = computeAuxCommitHash(
    executionId, taskId, senderId,
    paillierPublicKey, hatN, s, t,
    prmProof, rho_i, u_i
)

// 哈希内容:
SHA256("AUX_HASH_COM" || executionId || taskId || senderId ||
       paillierPublicKey || hatN || s || t || prmProof || rho_i || u_i)
```

### 2.3 广播数据

**消息类型**: `CGGMP_AUX_R1`

```json
{
  "taskId": "uuid",
  "executionId": "uuid",
  "senderId": 1,
  "V": "hex-encoded-hash"  // 承诺哈希
}
```

**传输方式**: RBC (可靠广播)

### 2.4 验证过程

```java
// 代码: CggmpAuxMessageHandler.handleCggmpAuxR1()

1. 接收并存储:
   task.commitHashes.put(senderId, V)
   task.commitLatch.countDown()

2. 等待所有节点的承诺收集完成
```

---

## 三、Round 1 Echo - 确认阶段

### 3.1 计算 Echo 哈希

```java
// 代码: CggmpProtocolUtils.computeAuxEchoHash()

// Echo = SHA256(executionId || taskId || sorted(all V_commits))
echo = SHA256(
    executionId,
    taskId,
    // 所有节点的 V_commit 按 nodeId 排序后拼接
    commit_1 || commit_2 || ... || commit_n
)
```

### 3.2 广播数据

**消息类型**: `CGGMP_AUX_R1_ECHO`

```json
{
  "taskId": "uuid",
  "executionId": "uuid",
  "senderId": 1,
  "hash": "sha256-hash"
}
```

### 3.3 验证过程

```java
// 代码: CggmpAuxMessageHandler.handleCggmpAuxR1Echo()

1. 接收其他节点的 Echo 哈希
2. 计算本地的 Echo 哈希
3. 验证:
   if (localEcho != receivedEcho) {
       task.fail("AUX echo mismatch")
   }

4. 记录验证结果:
   task.echoReceived.put(senderId, true)
   task.echoLatch.countDown()
```

**安全目的**: 确保所有节点都收到了 R1 承诺后，才能进入揭示阶段，防止Selective Attack。

---

## 四、Round 2 - 揭示阶段

### 4.1 广播数据

```java
// 代码: CggmpAuxProtocolHandler.runAuxProtocolAsync() - R2 部分

// 广播明文数据
{
  "taskId": "uuid",
  "executionId": "uuid",
  "senderId": 1,
  "paillierPublicKey": {
    "n": "hex-encoded",
    "nsquare": "hex-encoded",
    "g": "hex-encoded",
    "bitLength": 3072
  },
  "hatN": "hex-encoded",      // Pedersen 参数
  "s": "hex-encoded",
  "t": "hex-encoded",
  "prmProof": { ... },       // PRM 零知识证明
  "rho": "hex-encoded",
  "u": "hex-encoded"
}
```

### 4.2 验证过程

```java
// 代码: CggmpAuxMessageHandler.processAuxR2()

1. 验证承诺匹配:
   expectedCommit = computeAuxCommitHash(...)
   if (expectedCommit != storedCommit) {
       task.fail("AUX R2 commit mismatch")
   }

2. 验证 Paillier 位长度:
   if (publicKey.bitLength < auxMinPaillierBitsForProof) {  // 默认 2048
       task.fail("Paillier bit length too small")
   }

3. 验证 Pedersen 参数:
   if (hatN <= 0 || s <= 0 || t <= 0 ||
       s >= hatN || t >= hatN) {
       task.fail("Invalid Pedersen params")
   }

4. 验证 PRM 证明:
   prmCtx = buildAuxContext(taskId, executionId, senderId, "PRM")
   if (!verifyPrmProof(prmProof, hatN, s, t, prmCtx)) {
       task.fail("Invalid PiPrmProof")
   }

5. 存储验证通过的参数:
   task.peerPaillierKeys.put(senderId, publicKey)
   task.peerHatN.put(senderId, hatN)
   task.peerS.put(senderId, s)
   task.peerT.put(senderId, t)
   task.peerPrmProofs.put(senderId, prmProof)
   task.rho.put(senderId, rho)
   task.u.put(senderId, u)
   task.revealLatch.countDown()
```

---

## 五、Round 3 - 证明阶段

### 5.1 本地计算

```java
// 代码: CggmpAuxProtocolHandler.runAuxProtocolAsync() - R3 部分

1. 计算 XOR 随机数 (用于 MOD 证明):
   rho = xorAll(task.rho)  // 所有节点 rho_i 的 XOR

2. 生成 MOD 证明 (BiPrime Blum 证明):
   // 证明自己的 p, q 是两个大素数
   modCtx = buildAuxContext(taskId, executionId, nodeId, "MOD", rho)
   modProof = BiPrimeProofGenerator.createProof(
       paillierPrivateKey,  // p, q
       modCtx
   )

3. 生成 FAC 证明 (NoSmallFactor Proof):
   // 为每个其他节点生成证明，证明 p, q 无小因子
   for (peerId : participants) {
       if (peerId == nodeId) continue;

       hatN_peer = task.peerHatN.get(peerId)
       s_peer = task.peerS.get(peerId)
       t_peer = task.peerT.get(peerId)

       zk = new ZKSetup(hatN_peer, s_peer, t_peer)
       facProof = NoSmallFactorProofGenerator(zk)
           .createProof(paillierPrivateKey, modCtx)

       facProofs.put(peerId, facProof)
   }
```

### 5.2 广播数据

**消息类型**: `CGGMP_AUX_R3`

```json
{
  "taskId": "uuid",
  "executionId": "uuid",
  "senderId": 1,
  "modProof": {
    "N": "hex-encoded",        // n = p × q
    "w": "hex-encoded",
    "sigmas": ["hex", ...],   // 素数分解相关
    "xs": ["hex", ...],
    "zs": ["hex", ...],
    "aBits": "base64-encoded",
    "bBits": "base64-encoded",
    "sfRounds": 256,
    "blumRounds": 80
  },
  "facProofs": {
    "2": { ... },   // 对节点2的FAC证明
    "3": { ... },   // 对节点3的FAC证明
    ...
  }
}
```

### 5.3 验证过程

```java
// 代码: CggmpAuxMessageHandler.handleCggmpAuxR3()

1. 验证 MOD 证明 (BiPrime Blum):
   // 证明 sender 的 p, q 是两个大素数
   rho = xorAll(task.rho)
   modCtx = buildAuxContext(taskId, executionId, senderId, "MOD", rho)

   pk = task.peerPaillierKeys.get(senderId)
   if (!BI_PRIME_VALIDATOR.verifyProof(modProof, pk, modCtx)) {
       task.fail("Invalid AUX mod proof")
   }

2. 验证针对本节点的 FAC 证明:
   // 证明 sender 的 p, q 没有小因子
   facForMe = facProofs.get(String.valueOf(nodeId))
   hatN = task.hatN
   s = task.s
   t = task.t

   zk = new ZKSetup(hatN, s, t)
   facValidator = new NoSmallFactorProofValidator(zk, minBits)

   if (!facValidator.verifyProofDetailed(facProof, pk, modCtx).ok()) {
       task.fail("Invalid AUX fac proof")
   }

3. 存储证明:
   task.peerModProofs.put(senderId, modProof)
   task.peerFacProofs.put(senderId, facProof)
   task.proofLatch.countDown()
```

---

## 六、数据存储

### 6.1 最终 AUX 数据结构

```java
// 代码: CggmpAuxUtils.saveAuxInfo()

存储内容:
├── Paillier 公钥
│   ├── n = p × q           // 模数
│   ├── n²                   // 加密用
│   ├── g = n + 1            // 生成元
│   └── bitLength = 3072     // 位长度
│
├── Paillier 私钥 (本地存储)
│   ├── p, q                 // 素数
│   └── lambda = lcm(p-1, q-1)
│
└── ZKSetup (Pedersen 参数)
    ├── hatN = n²            // Pedersen 模数
    ├── h1                   // 承诺基点1
    └── h2                   // 承诺基点2
```

### 6.2 存储位置

- **本地节点**: 完整的 Paillier 密钥 (公钥 + 私钥)
- **其他节点**: 仅存储其他节点的 Paillier 公钥和 Pedersen 参数

---

## 七、安全机制汇总

| 阶段 | 安全机制 | 目的 |
|------|---------|------|
| R1 | V_commit 承诺 | 防止后续揭示阶段篡改数据 |
| R1-Echo | Echo 哈希验证 | 确保所有节点收到 R1，防止选择性透露 |
| R2 | PRM 证明 | 证明 Pedersen 参数由正确的 λ 生成 |
| R2 | 承诺验证 | 确保揭示的数据与承诺一致 |
| R3 | MOD 证明 (BiPrime) | 证明 p, q 是两个大素数 |
| R3 | FAC 证明 (NoSmallFactor) | 证明 p, q 无小因子，防止恶意密钥 |

---

## 八、完整数据流图

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         CGGMP AUX 完整数据流                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ Round 1 - 承诺阶段                                                     │   │
│  │                                                                        │   │
│  │  Local:                                                                │   │
│  │  ├── 生成 Paillier 密钥对 (p, q, n)                                   │   │
│  │  ├── 生成 Pedersen 参数 (hatN, h1, h2, lambda)                       │   │
│  │  ├── 生成随机数 (rho_i, u_i)                                          │   │
│  │  └── 生成 PRM 证明                                                     │   │
│  │                                                                        │   │
│  │  Compute: V = SHA256(paillierPK || hatN || s || t || prmProof || rho || u)   │   │
│  │                                                                        │   │
│  │  Broadcast (RBC): CGGMP_AUX_R1                                        │   │
│  │    { taskId, executionId, senderId, V }                              │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                    ↓                                         │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ Round 1 Echo - 确认阶段                                               │   │
│  │                                                                        │   │
│  │  Compute: Echo = SHA256(executionId || taskId || sorted(all V))     │   │
│  │                                                                        │   │
│  │  Broadcast (RBC): CGGMP_AUX_R1_ECHO                                  │   │
│  │    { taskId, executionId, senderId, hash }                          │   │
│  │                                                                        │   │
│  │  Verify: localEcho == receivedEcho                                   │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                    ↓                                         │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ Round 2 - 揭示阶段                                                     │   │
│  │                                                                        │   │
│  │  Broadcast: CGGMP_AUX_R2                                             │   │
│  │    {                                                                  │   │
│  │      paillierPublicKey: { n, n², g, bitLength }                     │   │
│  │      hatN, s, t: Pedersen 参数                                       │   │
│  │      prmProof: PRM 零知识证明                                         │   │
│  │      rho, u: 随机数                                                   │   │
│  │    }                                                                  │   │
│  │                                                                        │   │
│  │  Verify:                                                              │   │
│  │  ├── 承诺匹配验证: V == SHA256(revealed_data)                        │   │
│  │  ├── 位长度验证: bitLength >= 2048                                   │   │
│  │  ├── Pedersen 参数验证: s, t ∈ (0, hatN)                            │   │
│  │  └── PRM 证明验证                                                      │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                    ↓                                         │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ Round 3 - 证明阶段                                                     │   │
│  │                                                                        │   │
│  │  Local:                                                                │   │
│  │  ├── rho = XOR(all rho_i)                                            │   │
│  │  ├── 生成 MOD 证明 (BiPrime Blum): 证明 p, q 是大素数               │   │
│  │  └── 为每个节点生成 FAC 证明: 证明 p, q 无小因子                     │   │
│  │                                                                        │   │
│  │  Broadcast: CGGMP_AUX_R3                                             │   │
│  │    {                                                                  │   │
│  │      modProof: BiPrime 证明                                          │   │
│  │      facProofs: { peerId -> NoSmallFactor 证明 }                    │   │
│  │    }                                                                  │   │
│  │                                                                        │   │
│  │  Verify:                                                              │   │
│  │  ├── 验证 MOD 证明 (针对每个节点)                                     │   │
│  │  └── 验证针对本节点的 FAC 证明                                        │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                    ↓                                         │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ 保存 AUX                                                               │   │
│  │                                                                        │   │
│  │  本地: 完整 Paillier 密钥 + ZKSetup                                   │   │
│  │  其他节点: Paillier 公钥 + Pedersen 参数                              │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 九、消息类型汇总

| 消息类型 | 方向 | 传输方式 | 说明 |
|---------|------|---------|------|
| CGGMP_AUX_INIT | Broadcast | 点对点 | 初始化任务 |
| CGGMP_AUX_R1 | Broadcast | RBC | 承诺哈希 |
| CGGMP_AUX_R1_ECHO | Broadcast | RBC | 确认哈希 |
| CGGMP_AUX_R2 | Broadcast | 点对点 | 揭示参数 |
| CGGMP_AUX_R3 | Broadcast | 点对点 | 零知识证明 |
| CGGMP_AUX_STATUS | Broadcast | 点对点 | AUX 状态查询 |

---

## 十、代码位置

| 功能 | 文件 |
|------|------|
| 入口 | `CggmpAuxService.startAuxProcess()` |
| 协议处理 | `CggmpAuxProtocolHandler.runAuxProtocolAsync()` |
| 消息处理 | `CggmpAuxMessageHandler.handleCggmpAux*()` |
| 工具方法 | `CggmpAuxUtils.saveAuxInfo()` |
| 哈希计算 | `CggmpProtocolUtils.computeAuxCommitHash()` |
| 任务管理 | `CggmpAuxTask` |

---

## 十一、关键参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| auxPaillierBits | 3072 | Paillier 密钥位长度 |
| auxMinPaillierBitsForProof | 2048 | 证明所需最小位长度 |
| AUX_ROUND_TIMEOUT_SECONDS | 120 | 每轮超时时间 |

---

## 十二、错误处理

| 错误类型 | 处理方式 |
|---------|---------|
| Echo 不匹配 | 任务失败，报告 senderId |
| Commit 不匹配 | 任务失败，报告 senderId |
| PRM 证明无效 | 任务失败，记录详细日志 |
| MOD 证明无效 | 任务失败 |
| FAC 证明无效 | 任务失败 |
| 超时 | 重试机制，最多3次 |
