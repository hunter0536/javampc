# Simple 分布式签名完整流程详解

## 1. 概述

Simple 签名是一个**分布式 ECDSA 签名**方案，多个节点协作生成签名，无需暴露任何节点的完整私钥。

## 2. 预备知识

### 2.1 ECDSA 签名基础

普通 ECDSA 签名流程：

```
输入：私钥 x，消息 m
输出：签名 (r, s)

1. 选择随机数 k
2. 计算 R = G × k（G 是椭圆曲线生成点）
3. r = R.x mod n（n 是曲线阶）
4. s = k⁻¹ × (H(m) + r × x) mod n
5. 签名 = (r, s)
```

### 2.2 符号说明

| 符号 | 含义 |
|------|------|
| G | 椭圆曲线 secp256k1 的生成点 |
| n | 椭圆曲线阶 |
| x_i | 节点 i 的私钥份额 |
| X | 群公钥 = G × x（x = Σ x_i） |
| H(m) | 消息 m 的哈希值（SHA-256） |
| k_i | 节点 i 生成的随机数 |
| R | 临时公钥 = G × k（k = Σ k_i） |
| σ_i | 节点 i 的签名份额 |

---

## 3. 分布式签名流程

### 3.1 整体架构

```
┌─────────────────────────────────────────────────────────────────┐
│                     Simple 签名两阶段                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  阶段一：离线阶段 (Offline Phase)                               │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ 1. 每个节点生成随机数 k_i, γ_i                          │   │
│  │ 2. 计算Commitment: R_i = G × k_i, Γ_i = G × γ_i        │   │
│  │ 3. 广播 R_i, Γ_i                                        │   │
│  │ 4. 收集所有 R_i, Γ_i                                    │   │
│  │ 5. 聚合: R = Σ R_i, Γ = Σ Γ_i                          │   │
│  └─────────────────────────────────────────────────────────┘   │
│                           ↓                                      │
│  阶段二：在线阶段 (Online Phase)                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ 1. 计算 r = R.x mod n                                    │   │
│  │ 2. 每个节点计算 σ_i = k_i⁻¹ × (H(m) + r × x_i) mod n    │   │
│  │ 3. 广播 σ_i                                              │   │
│  │ 4. 收集所有 σ_i                                          │   │
│  │ 5. 聚合: s = Σ σ_i mod n                                 │   │
│  │ 6. 最终签名: (r, s)                                      │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 4. 阶段一：离线阶段

### 4.1 目的

为每个签名会话生成**临时的随机数Commitment**，确保签名的随机性和不可预测性。

### 4.2 详细步骤

#### 步骤 1：生成随机数

每个节点 i 独立生成两个随机数：

```
k_i = random(1, n-1)    // 临时私钥
γ_i = random(1, n-1)    // 另一个随机数（用于抗攻击）
```

**注意**：k_i 必须非零且小于 n。

#### 步骤 2：计算 Commitment

```
R_i = G × k_i           // 临时公钥
Γ_i = G × γ_i           // 另一个 Commitment
```

#### 步骤 3：广播

节点 i 广播 (R_i, Γ_i) 给所有其他节点。

#### 步骤 4：收集

每个节点等待收集**所有参与节点**的 (R_i, Γ_i)：

```
R = Σ R_i  (在椭圆曲线上点加法)
Γ = Σ Γ_i
```

#### 步骤 5：结果

最终得到聚合的 R 和 Γ，用于下一阶段。

### 4.3 数学公式

```
R = Σ (G × k_i) = G × (Σ k_i) = G × k_total
其中 k_total = Σ k_i mod n

Γ = Σ (G × γ_i) = G × (Σ γ_i) = G × γ_total
其中 γ_total = Σ γ_i mod n
```

---

## 5. 阶段二：在线阶段

### 5.1 目的

使用离线阶段准备的 R，计算实际的签名值 s。

### 5.2 详细步骤

#### 步骤 1：计算 r

从聚合的 R 计算 r 值：

```
r = R.x mod n

其中 R.x 是 R 点的 x 坐标
```

**如果 r = 0，签名失败，需要重新执行离线阶段。**

#### 步骤 2：加载私钥

从本地或数据库加载自己的私钥份额：

```
x_i = loadPrivateKey()
```

#### 步骤 3：计算签名份额 σ_i

**核心公式**：

```
σ_i = k_i⁻¹ × (H(m) + r × x_i) mod n
```

**推导**：
- k_i⁻¹ 是 k_i 在模 n 下的乘法逆元
- H(m) 是消息的哈希值
- r 是上一步计算的 r 值
- x_i 是节点的私钥份额

#### 步骤 4：广播 σ_i

节点 i 广播 σ_i 给所有其他节点。

#### 步骤 5：收集 σ_i

每个节点等待收集**所有参与节点**的 σ_i：

```
σ_shares = {σ_1, σ_2, σ_3, ..., σ_n}
```

#### 步骤 6：聚合 s

**关键公式**：

```
s = Σ σ_i mod n

代入 σ_i：
s = Σ [k_i⁻¹ × (H(m) + r × x_i)] mod n
  = H(m) × Σ k_i⁻¹ + r × Σ (k_i⁻¹ × x_i) mod n
```

#### 步骤 7：最终签名

```
签名 = (r, s)
```

---

## 6. 签名验证

### 6.1 验证公式

给定消息 m、签名 (r, s)、群公钥 X：

```
s⁻¹ × G ?= s⁻¹ × H(m) × G + s⁻¹ × r × X
简化：
G ?= H(m) × s⁻¹ × G + r × s⁻¹ × X
```

### 6.2 验证过程

```
1. 计算 s⁻¹ mod n
2. 计算 u1 = H(m) × s⁻¹ mod n
3. 计算 u2 = r × s⁻¹ mod n
4. 计算 P = u1 × G + u2 × X
5. 验证 P.x mod n == r
```

---

## 7. 完整流程图

```
节点 1              节点 2              节点 3
  │                   │                   │
  │  生成 k₁,γ₁      │  生成 k₂,γ₂       │  生成 k₃,γ₃
  │  R₁=G×k₁        │  R₂=G×k₂          │  R₃=G×k₃
  │  Γ₁=G×γ₁        │  Γ₂=G×γ₂          │  Γ₃=G×γ₃
  │                   │                   │
  ├─R₁,Γ₁──────────→│                   │
  │←─R₂,Γ₂──────────┤                   │
  │                   │                   │
  │              ├─R₂,Γ₂──────────→    │
  │              │←─R₃,Γ₃─────────────┤
  │                   │                   │
  │  ←────────────R₃,Γ₃───────────────┤
  │                   │                   │
  │  R = R₁+R₂+R₃                         │
  │  r = R.x mod n                        │
  │                   │                   │
  │  σ₁ = k₁⁻¹(H(m)+r·x₁)                │
  ├─σ₁────────────→│                   │
  │←─σ₂────────────┤                   │
  │                   │                   │
  │              σ₂ = k₂⁻¹(H(m)+r·x₂)    │
  │              ├─σ₂────────────→        │
  │              │←─σ₃─────────────────┤
  │                   │                   │
  │  ←─────────────σ₃────────────────┤
  │                   │                   │
  │  s = σ₁+σ₂+σ₃ mod n                │
  │  签名 = (r, s)                       │
  │  验证签名                               │
  │                   │                   │
```

---

## 8. 安全性分析

### 8.1 隐私性

- **k_i 不暴露**：只广播 R_i = G × k_i，不暴露 k_i
- **x_i 不暴露**：每个节点只知道自己的 x_i，不知道其他节点的
- **最终私钥不暴露**：即使知道所有 σ_i，也无法推出 x_i

### 8.2 正确性

- 验证公式基于 ECDSA 标准
- 聚合的 s 等同于使用等效私钥 x_total 签名的结果

### 8.3 抗攻击

- **γ_i 的作用**：防止恶意节点通过选择特定的 k_i 来窃取私钥
- **DKG 阈值**：即使部分节点离线，仍可完成签名

---

## 9. 与普通 ECDSA 对比

| 步骤 | 普通 ECDSA | Simple 分布式 |
|------|------------|--------------|
| 随机数 | 1 个 k | n 个 k_i |
| 私钥 | 1 个 x | n 个 x_i |
| 签名计算 | s = k⁻¹(H+rx) | σ_i = k_i⁻¹(H+rx_i) |
| 最终 s | s 直接计算 | s = Σ σ_i |

---

## 10. 代码实现

### 10.1 核心代码位置

| 步骤 | 方法 | 行号 |
|------|------|------|
| 入口 | `runSignature()` | SimpleSignatureService L132 |
| 离线阶段 | `runOfflinePhase()` | SimpleSignatureService L146 |
| 在线阶段 | `runOnlinePhase()` | SimpleSignatureService L180 |
| 广播 R | `broadcastOfflineData()` | SimpleSignatureService L247 |
| 广播 σ | `broadcastSigmaShare()` | SimpleSignatureService L258 |
| 等待 R | `waitForOfflinePhase()` | SimpleSignatureService L327 |
| 等待 σ | `waitForSigmaShares()` | SimpleSignatureService L350 |
| 聚合点 | `sumPoints()` | SimpleSignatureService L401 |
| 聚合数 | `sumBigIntegers()` | SimpleSignatureService L415 |

### 10.2 关键代码片段

#### 生成随机数
```java
task.k_i = randomNonZero(curveOrder);
task.gamma_i = randomNonZero(curveOrder);
```

#### 计算 R
```java
task.R = Secp256k1Curve.multiply(Secp256k1Curve.G(), task.k_i).normalize();
```

#### 计算 sigma_i
```java
BigInteger kInv = task.k_i.modInverse(curveOrder);
BigInteger sigma_i = kInv.multiply(messageHash.add(r.multiply(privateKey))).mod(curveOrder);
```

#### 聚合 s
```java
BigInteger s = sumBigIntegers(task.sigmaShares, curveOrder);
```

---

## 11. Simple vs CGGMP 对比

| 特性 | Simple | CGGMP |
|------|--------|-------|
| 复杂度 | 简单 | 复杂 |
| 安全性 | 较低 | 高（零知识证明） |
| 消息轮数 | 2 轮 | 多轮 |
| 阈值支持 | 否 (n-n) | 是 (t-n) |
| 预签名 | 无 | 有 |
| 广播 k_i | 否（只广播 R） | 否 |

---

## 12. 参考资料

- [ECDSA 签名算法](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm)
- [DKG 分布式密钥生成](https://en.wikipedia.org/wiki/Distributed_key_generation)
- [CGGMP 阈值签名](https://eprint.iacr.org/2020/540)
