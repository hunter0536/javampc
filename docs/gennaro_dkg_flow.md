# Gennaro DKG 协议流程

## 概述

Gennaro DKG (Distributed Key Generation) 是一种安全的分布式密钥生成协议，允许多个节点共同生成密钥对，而无需信任任何单一节点。本实现基于 Gennaro 等人提出的可验证秘密共享方案。

## 协议参数

- **节点数量**: 5 个节点
- **阈值**: 3-of-5 (任意 3 个份额可恢复密钥)
- **椭圆曲线**: secp256k1

## 流程图

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          Gennaro DKG 协议流程                                │
└─────────────────────────────────────────────────────────────────────────────┘

节点A (发起方)                      节点B, C, D, E (参与方)
     │                                    │
     │  1. 创建任务 & 生成多项式            │
     │  f(x) = a₀ + a₁x + a₂x + ...       │
     │  m(x) = 0  + m₁x + m₂x + ...       │
     │  V_i = G·a_i, W_i = G·m_i          │
     │                                    │
     │  2. 广播 GENNARO_DKG_INIT           │
     │ ──────────────────────────────────> │
     │                                    │ 收到后创建本地任务
     │                                    │ 生成自己的多项式
     │  3. 广播 GENNARO_COMMITMENT         │
     │    (验证点 V, W)                    │
     │ ──────────────────────────────────> │
     │ <────────────────────────────────── │ 广播各自的 COMMITMENT
     │                                    │
     │  4. 等待所有承诺 & 验证              │
     │                                    │
     │  5. 计算份额 & 点对点发送            │
     │    s_B = f(B) + m(B)               │
     │ ──────────────────────────────────> │ GENNARO_SHARE (发给B)
     │ ──────────────────────────────────> │ GENNARO_SHARE (发给C)
     │ ──────────────────────────────────> │ ...
     │ <────────────────────────────────── │ 收到其他节点的份额
     │                                    │
     │  6. 验证份额 & 计算最终密钥份额       │
     │    sk = Σ s_j(i)                   │
     │                                    │
     │  7. 广播公钥贡献 GENNARO_PUBLIC_KEY_PART
     │    (V₀ = G·a₀)                     │
     │ ──────────────────────────────────> │
     │ <────────────────────────────────── │
     │                                    │
     │  8. 计算群公钥                       │
     │    PK = Σ V₀_j                     │
     │                                    │
     │  9. 保存密钥份额到数据库              │
     ▼                                    ▼
```

## 详细步骤

### 步骤 1: 任务初始化

发起节点创建 DKG 任务，生成唯一的任务 ID：

```java
String taskId = UUID.randomUUID().toString();
GennaroDkgTask task = new GennaroDkgTask(taskId, nodesCount);
```

### 步骤 2: 多项式生成

每个节点生成两个多项式：

**秘密多项式** (degree = threshold - 1):
```
f(x) = a₀ + a₁x + a₂x² + ... + a_{t-1}x^{t-1}
```
- a₀ 是该节点对最终密钥的贡献
- 其他系数随机生成

**掩码多项式** (常数项为 0):
```
m(x) = 0 + m₁x + m₂x² + ... + m_{t-1}x^{t-1}
```
- 常数项为 0，不影响最终密钥
- 用于提供可验证性

```java
task.coefficients = generateRandomPolynomial(Constants.THRESHOLD - 1);
task.maskingCoefficients = generateMaskingPolynomial(Constants.THRESHOLD - 1);
```

### 步骤 3: 验证点计算

计算验证点用于后续验证份额：

```
V_i = G · a_i  (秘密多项式系数的承诺)
W_i = G · m_i  (掩码多项式系数的承诺)
```

```java
task.verificationPoints = generateVerificationPoints(task.coefficients);
task.maskingVerificationPoints = generateVerificationPoints(task.maskingCoefficients);
```

### 步骤 4: 承诺广播 (GENNARO_COMMITMENT)

每个节点广播自己的验证点：

```java
Map<String, Object> commitmentData = new HashMap<>();
commitmentData.put("taskId", taskId);
commitmentData.put("verificationPoints", encodedVerificationPoints);
commitmentData.put("maskingVerificationPoints", encodedMaskingVerificationPoints);
nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.GENNARO_COMMITMENT, commitmentData));
```

### 步骤 5: 份额计算与分发 (GENNARO_SHARE)

为每个节点计算份额并点对点发送：

```
s_j = f(j) + m(j) mod q
```

其中 j 是目标节点的 ID。

```java
BigInteger actualShare = evaluatePolynomial(task.coefficients, BigInteger.valueOf(nodeInfo.id));
BigInteger maskingShare = evaluatePolynomial(task.maskingCoefficients, BigInteger.valueOf(nodeInfo.id));
BigInteger combinedShare = actualShare.add(maskingShare).mod(getCurveOrder());
nodeService.sendMessage(nodeInfo.id, new NodeService.Message(nodeId, MessageType.GENNARO_SHARE, shareData));
```

### 步骤 6: 份额验证

接收方使用验证点验证份额的正确性：

验证公式：
```
G · s_i = Σ_{j=0}^{t-1} V_j · i^j + Σ_{j=0}^{t-1} W_j · i^j
```

```java
ECPoint gShare = G.multiply(share);
ECPoint computedActualPoint = verificationPoints.get(0);
for (int i = 1; i < verificationPoints.size(); i++) {
    xPower = xPower.multiply(xBigInt);
    ECPoint viPower = verificationPoints.get(i).multiply(xPower);
    computedActualPoint = computedActualPoint.add(viPower);
}
// 类似计算 computedMaskingPoint
ECPoint computedTotalPoint = computedActualPoint.add(computedMaskingPoint);
return gShare.equals(computedTotalPoint);
```

### 步骤 7: 计算最终密钥份额

每个节点聚合收到的所有份额：

```
sk_i = Σ_{j=1}^{n} s_j(i) mod q
```

包括自己为自己计算的份额。

```java
task.finalKeyShare = BigInteger.ZERO;
for (BigInteger share : task.receivedShares.values()) {
    task.finalKeyShare = task.finalKeyShare.add(share).mod(curveOrder);
}
// 加上自己的份额
BigInteger selfActualShare = evaluatePolynomial(task.coefficients, BigInteger.valueOf(nodeId));
BigInteger selfMaskingShare = evaluatePolynomial(task.maskingCoefficients, BigInteger.valueOf(nodeId));
task.finalKeyShare = task.finalKeyShare.add(selfActualShare.add(selfMaskingShare)).mod(curveOrder);
```

### 步骤 8: 群公钥生成 (GENNARO_PUBLIC_KEY_PART)

每个节点广播自己的公钥贡献 V₀ = G · a₀：

```java
ECPoint myContribution = task.verificationPoints.get(0);
nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.GENNARO_PUBLIC_KEY_PART, publicKeyData));
```

聚合计算群公钥：

```
PK = Σ_{j=1}^{n} V₀_j = G · Σ_{j=1}^{n} a₀_j
```

```java
ECPoint groupPublicKeyPoint = allContributions.get(0);
for (int i = 1; i < allContributions.size(); i++) {
    groupPublicKeyPoint = groupPublicKeyPoint.add(allContributions.get(i));
}
```

### 步骤 9: 保存密钥份额

将密钥份额保存到本地数据库：

```java
String shareHex = HexUtils.toHex(task.finalKeyShare);
KeyShare keyShare = new KeyShare(nodeId, shareHex, task.groupPublicKey, task.taskId);
keyShareDao.save(keyShare);
```

## 消息类型

| 消息类型 | 传播方式 | 内容 | 用途 |
|---------|---------|------|------|
| `GENNARO_DKG_INIT` | 广播 | taskId | 通知所有节点开始 DKG |
| `GENNARO_COMMITMENT` | 广播 | 验证点 V, W | 承诺阶段，用于验证份额 |
| `GENNARO_SHARE` | 点对点 | 份额 s | 分发密钥份额 |
| `GENNARO_PUBLIC_KEY_PART` | 广播 | V₀ 或群公钥 | 聚合生成群公钥 |

## 数学原理

### 双多项式方案

Gennaro DKG 使用双多项式方案提供可验证性：

1. **秘密多项式 f(x)**: 常数项 a₀ 是对最终密钥的贡献
2. **掩码多项式 m(x)**: 常数项为 0，不影响最终密钥

最终密钥：
```
sk = Σ_{j=1}^{n} a₀_j
```

### 可验证性

份额验证确保：
- 份额确实是由承诺的多项式计算得出
- 任何节点都无法发送虚假份额

### 阈值特性

使用 Shamir 秘密共享的 (t, n) 门限方案：
- 任意 t 个份额可以恢复完整密钥
- 少于 t 个份额无法获得任何信息

## 安全性

1. **无单点故障**: 没有任何节点知道完整密钥
2. **可验证性**: 每个份额都可以被验证
3. **抗合谋**: 少于 t 个节点合谋无法恢复密钥
4. **前向安全**: 即使某些份额泄露，其他份额仍然安全

## 代码参考

- 服务实现: [GennaroDkgService.java](../src/main/java/com/example/mpc/service/GennaroDkgService.java)
- 任务模型: [GennaroDkgTask.java](../src/main/java/com/example/mpc/dto/GennaroDkgTask.java)
- 消息类型: [MessageType.java](../src/main/java/com/example/mpc/enums/MessageType.java)
