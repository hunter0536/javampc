# 零知识验证技术综述

## 概述

零知识证明（Zero-Knowledge Proof, ZKP）是一种密码学协议，允许证明者向验证者证明某个陈述为真，而不泄露任何额外信息。

**核心性质**：
- **完备性（Completeness）**：诚实证明者总能说服诚实验证者
- **可靠性（Soundness）**：恶意证明者无法欺骗验证者
- **零知识性（Zero-Knowledge）**：验证者除了陈述为真外，学不到任何其他信息

---

## 1. Schnorr 协议

### 1.1 基本原理

最经典的零知识证明协议，用于证明知道离散对数。

**场景**：证明知道 x，使得 Y = G^x

```
证明者 (P)                         验证者 (V)
    │                                  │
    │  1. 选择随机数 r                  │
    │     计算 R = G^r                 │
    │                                  │
    │  ──── 发送 R ─────────────────>  │
    │                                  │
    │  <──── 发送随机挑战 c ──────────  │
    │                                  │
    │  2. 计算 s = r + c·x             │
    │                                  │
    │  ──── 发送 s ─────────────────>  │
    │                                  │ 验证: G^s = R · Y^c
    │                                  │
```

### 1.2 代码实现

```java
public class SchnorrProof {
    private final ECPoint R;
    private final BigInteger s;
    
    public static SchnorrProof prove(BigInteger x, ECPoint G, BigInteger curveOrder) {
        SecureRandom random = new SecureRandom();
        BigInteger r = new BigInteger(256, random).mod(curveOrder);
        ECPoint R = G.multiply(r);
        // 在实际应用中，c 通过 Fiat-Shamir 变换计算
        BigInteger c = hashToBigInteger(R.getEncoded());
        BigInteger s = r.add(c.multiply(x)).mod(curveOrder);
        return new SchnorrProof(R, s);
    }
    
    public boolean verify(ECPoint Y, ECPoint G, BigInteger curveOrder) {
        BigInteger c = hashToBigInteger(R.getEncoded());
        ECPoint left = G.multiply(s);
        ECPoint right = R.add(Y.multiply(c));
        return left.equals(right);
    }
}
```

### 1.3 特点

| 特性 | 说明 |
|-----|------|
| 交互轮数 | 3 轮 |
| 证明大小 | 2 个群元素 |
| 安全假设 | 离散对数困难性 |
| 适用场景 | 身份认证、数字签名 |

---

## 2. Fiat-Shamir 变换

### 2.1 基本原理

将交互式协议转为非交互式，用密码学哈希函数替代验证者的随机挑战。

```
证明者：
  R = G^r
  c = H(R || Y || message)  // 哈希替代随机挑战
  s = r + c·x
  发送 (R, s)

验证者：
  c = H(R || Y || message)
  验证: G^s = R · Y^c
```

### 2.2 代码实现

```java
public class NonInteractiveSchnorr {
    public static Proof prove(BigInteger x, ECPoint Y, ECPoint G, 
                              byte[] message, BigInteger curveOrder) {
        SecureRandom random = new SecureRandom();
        BigInteger r = new BigInteger(256, random).mod(curveOrder);
        ECPoint R = G.multiply(r);
        
        // Fiat-Shamir: 用哈希生成挑战
        byte[] cBytes = hash(concat(R.getEncoded(), Y.getEncoded(), message));
        BigInteger c = new BigInteger(1, cBytes).mod(curveOrder);
        
        BigInteger s = r.add(c.multiply(x)).mod(curveOrder);
        return new Proof(R, s);
    }
    
    public static boolean verify(Proof proof, ECPoint Y, ECPoint G,
                                  byte[] message, BigInteger curveOrder) {
        byte[] cBytes = hash(concat(proof.R.getEncoded(), Y.getEncoded(), message));
        BigInteger c = new BigInteger(1, cBytes).mod(curveOrder);
        
        ECPoint left = G.multiply(proof.s);
        ECPoint right = proof.R.add(Y.multiply(c));
        return left.equals(right);
    }
}
```

### 2.3 特点

| 特性 | 说明 |
|-----|------|
| 交互轮数 | 1 轮（非交互） |
| 证明大小 | 2 个元素 |
| 安全假设 | 随机预言机模型 |
| 适用场景 | 数字签名、区块链 |

---

## 3. Pedersen 承诺

### 3.1 基本原理

一种加法同态的承诺方案，用于在不泄露值的情况下承诺一个值。

**承诺公式**：
```
C = G^v · H^r

其中：
- v 是要承诺的值
- r 是随机盲化因子
- G, H 是独立的生成元（必须无法找到 H = G^x）
```

### 3.2 同态性质

```
C₁ = G^v₁ · H^r₁
C₂ = G^v₂ · H^r₂

C₁ · C₂ = G^(v₁+v₂) · H^(r₁+r₂)
```

### 3.3 代码实现

```java
public class PedersenCommitment {
    private final ECPoint G;
    private final ECPoint H;  // 独立生成元
    
    public Commitment commit(BigInteger v, BigInteger r) {
        ECPoint C = G.multiply(v).add(H.multiply(r));
        return new Commitment(C, v, r);
    }
    
    public boolean verify(Commitment comm) {
        ECPoint expected = G.multiply(comm.v).add(H.multiply(comm.r));
        return comm.C.equals(expected);
    }
    
    // 证明 v₁ + v₂ = v₃
    public boolean verifySum(Commitment c1, Commitment c2, Commitment c3) {
        ECPoint left = c1.C.add(c2.C);
        ECPoint right = c3.C;
        return left.equals(right);
    }
}
```

### 3.4 特点

| 特性 | 说明 |
|-----|------|
| 隐藏性 | 无法从 C 推断 v |
| 绑定性 | 无法找到不同的 (v, r) 产生相同的 C |
| 同态性 | 支持加法运算 |
| 适用场景 | 保密交易、投票系统、DKG |

---

## 4. Chaum-Pedersen 协议

### 4.1 基本原理

证明两个离散对数相等，即 log_G(Y) = log_H(Z)。

```
证明者 (P)                         验证者 (V)
    │                                  │
    │  R₁ = G^r, R₂ = H^r              │
    │  ─────────────────────────────>  │
    │  <──── 发送挑战 c ──────────────  │
    │  s = r + c·x                     │
    │  ─────────────────────────────>  │
    │                                  │ 验证: G^s = R₁·Y^c
    │                                  │       H^s = R₂·Z^c
```

### 4.2 代码实现

```java
public class ChaumPedersenProof {
    public static Proof prove(BigInteger x, ECPoint G, ECPoint H,
                              ECPoint Y, ECPoint Z, BigInteger curveOrder) {
        SecureRandom random = new SecureRandom();
        BigInteger r = new BigInteger(256, random).mod(curveOrder);
        
        ECPoint R1 = G.multiply(r);
        ECPoint R2 = H.multiply(r);
        
        BigInteger c = hash(R1.getEncoded(), R2.getEncoded(), 
                           Y.getEncoded(), Z.getEncoded());
        
        BigInteger s = r.add(c.multiply(x)).mod(curveOrder);
        return new Proof(R1, R2, s);
    }
    
    public static boolean verify(Proof proof, ECPoint G, ECPoint H,
                                  ECPoint Y, ECPoint Z, BigInteger curveOrder) {
        BigInteger c = hash(proof.R1.getEncoded(), proof.R2.getEncoded(),
                           Y.getEncoded(), Z.getEncoded());
        
        ECPoint left1 = G.multiply(proof.s);
        ECPoint right1 = proof.R1.add(Y.multiply(c));
        
        ECPoint left2 = H.multiply(proof.s);
        ECPoint right2 = proof.R2.add(Z.multiply(c));
        
        return left1.equals(right1) && left2.equals(right2);
    }
}
```

### 4.3 应用场景

- 证明加密密钥与签名密钥相同
- 可验证加密
- 匿名凭证系统

---

## 5. 范围证明

### 5.1 Bulletproofs

当前最高效的范围证明方案，证明一个值在 [0, 2^n) 范围内。

**特点**：
- 证明大小：O(log n)，非常紧凑
- 无需可信设置
- 支持聚合证明

```
证明大小对比（证明 64 位整数在范围内）：
- 传统方法：约 13 KB
- Bulletproofs：约 1.5 KB
- 聚合 16 个证明：约 2.5 KB
```

### 5.2 代码示例（概念）

```java
public class BulletproofRange {
    // 证明 v ∈ [0, 2^n)
    public static RangeProof prove(BigInteger v, BigInteger r, 
                                    ECPoint G, ECPoint H, int n) {
        // 1. 创建承诺 C = G^v · H^r
        // 2. 将 v 分解为比特向量
        // 3. 构建内积证明
        // 4. 生成聚合证明
        return new RangeProof(...)
    }
    
    public static boolean verify(RangeProof proof, ECPoint C, int n) {
        // 验证内积证明
        // 验证范围约束
        return true;
    }
}
```

### 5.3 应用场景

| 场景 | 说明 |
|-----|------|
| 保密交易 | 证明交易金额为正数 |
| 年龄验证 | 证明年龄大于某个值 |
| 信用评分 | 证明评分在某个范围 |
| 拍卖系统 | 证明出价在有效范围 |

---

## 6. zk-SNARKs

### 6.1 基本原理

零知识简洁非交互式知识论证（Zero-Knowledge Succinct Non-Interactive Argument of Knowledge）。

**核心特点**：
- **简洁（Succinct）**：证明大小常数级，验证时间常数级
- **非交互（Non-Interactive）**：单次通信
- **需要可信设置（Trusted Setup）**：生成公共参数

### 6.2 流程

```
1. 可信设置阶段：
   生成 (pk, vk) = Setup(circuit)
   - pk: 证明密钥（公开）
   - vk: 验证密钥（公开）
   - 需要销毁有毒废料

2. 证明阶段：
   π = Prove(pk, statement, witness)

3. 验证阶段：
   result = Verify(vk, statement, π) → true/false
```

### 6.3 代码示例（概念）

```java
public class ZkSnark {
    // 可信设置
    public static KeyPair setup(Circuit circuit) {
        // 生成 CRS (Common Reference String)
        // 需要多方参与的可信设置仪式
        return new KeyPair(provingKey, verificationKey);
    }
    
    // 生成证明
    public static Proof prove(ProvingKey pk, 
                               Object[] publicInputs,
                               Object[] privateWitness) {
        // 1. 将计算转换为 R1CS 约束系统
        // 2. 在约束上生成证明
        // 3. 输出简洁证明
        return new Proof(...)
    }
    
    // 验证证明
    public static boolean verify(VerificationKey vk,
                                  Object[] publicInputs,
                                  Proof proof) {
        // 常数时间验证
        return true;
    }
}
```

### 6.4 特点

| 特性 | 说明 |
|-----|------|
| 证明大小 | ~200 字节 |
| 验证时间 | 毫秒级 |
| 可信设置 | 需要 |
| 抗量子 | 否 |
| 适用场景 | Zcash、Filecoin、zkRollup |

---

## 7. zk-STARKs

### 7.1 基本原理

零知识可扩展透明知识论证（Zero-Knowledge Scalable Transparent Argument of Knowledge）。

**核心特点**：
- **透明（Transparent）**：无需可信设置
- **可扩展（Scalable）**：验证时间与证明大小呈对数增长
- **抗量子**：基于哈希函数

### 7.2 与 zk-SNARKs 对比

| 特性 | zk-SNARKs | zk-STARKs |
|-----|-----------|-----------|
| 可信设置 | 需要 | 不需要 |
| 证明大小 | 常数级 | O(log² n) |
| 验证时间 | 常数级 | O(log² n) |
| 抗量子 | 否 | 是 |
| 安全假设 | 指数知识假设 | 哈希函数安全性 |

### 7.3 代码示例（概念）

```java
public class ZkStark {
    // 无需可信设置
    
    public static Proof prove(Circuit circuit,
                               Object[] publicInputs,
                               Object[] privateWitness) {
        // 1. 算术化：将计算转换为代数中间表示
        // 2. 低度扩展：在更大域上扩展执行轨迹
        // 3. FRI 协议：证明多项式低度
        return new Proof(...)
    }
    
    public static boolean verify(Proof proof,
                                  Object[] publicInputs) {
        // 验证 FRI 证明
        // 验证约束满足
        return true;
    }
}
```

---

## 8. Sigma 协议家族

### 8.1 概述

Sigma 协议是一类三步交互式零知识证明协议的统称。

**标准形式**：
```
证明者                    验证者
   │                         │
   │  承诺         │
   │ ──────────────────────> │
   │ <────────────────────── │ 挑战
   │                         │
   │  响应          │
   │ ──────────────────────> │
   │                         │ 验证
```

### 8.2 常见变体

| 协议 | 证明内容 | 应用 |
|-----|---------|------|
| Schnorr | 知道离散对数 | 身份认证 |
| Chaum-Pedersen | 两个离散对数相等 | 可验证加密 |
| Okamoto | 知道多个离散对数的线性组合 | 增强安全性 |
| Cramer-Damgård-Schoenmakers | OR 证明 | 匿名投票 |
| Camenisch-Stadler | 范围证明 | 年龄验证 |

### 8.3 OR 证明示例

证明满足条件之一，不泄露具体满足哪个：

```
证明：知道 x₁ 使得 Y₁ = G^x₁  或  知道 x₂ 使得 Y₂ = G^x₂

证明者构造：
- 对真实条件：生成真实证明
- 对虚假条件：模拟证明（选择挑战）
- 调整挑战使得 c₁ + c₂ = c（验证者的挑战）
```

---

## 9. MPC 中的应用

### 9.1 Gennaro DKG 中的验证

使用 Pedersen 承诺变体：

```java
// 验证点（承诺）
V_i = G · a_i
W_i = G · m_i

// 份额验证
G · s_j = Σ V_i · j^i + Σ W_i · j^i
```

**优点**：
- 非交互式
- 计算效率高
- 通信开销小

### 9.2 GG20 签名中的验证

使用多种零知识技术：

| 阶段 | 使用的技术 |
|-----|-----------|
| MT (Multiplicative-to-Additive) | 范围证明 |
| 密钥生成 | Schnorr 协议 |
| 签名生成 | Chaum-Pedersen |

---

## 10. 技术对比总结

### 10.1 性能对比

| 方法 | 交互轮数 | 证明大小 | 验证复杂度 | 可信设置 |
|-----|---------|---------|-----------|---------|
| Schnorr | 3 | 2 元素 | O(1) | 否 |
| Fiat-Shamir | 1 | 2 元素 | O(1) | 否 |
| Pedersen 承诺 | 1 | O(t) | O(t) | 否 |
| Bulletproofs | 1 | O(log n) | O(n) | 否 |
| zk-SNARKs | 1 | O(1) | O(1) | 是 |
| zk-STARKs | 1 | O(log² n) | O(log² n) | 否 |

### 10.2 适用场景

| 场景 | 推荐方案 | 原因 |
|-----|---------|------|
| DKG 份额验证 | Pedersen 承诺 | 非交互、高效 |
| 数字签名 | Schnorr/Fiat-Shamir | 简单、标准 |
| 保密交易 | Bulletproofs | 紧凑的范围证明 |
| 复杂电路证明 | zk-SNARKs | 证明最小 |
| 抗量子需求 | zk-STARKs | 基于哈希 |
| 身份认证 | Schnorr | 交互式验证 |

### 10.3 安全假设

| 方案 | 安全假设 |
|-----|---------|
| Schnorr/Fiat-Shamir | 离散对数困难性 |
| Pedersen 承诺 | 离散对数困难性 + 独立生成元 |
| Bulletproofs | 离散对数困难性 |
| zk-SNARKs | 指数知识假设 + 可信设置 |
| zk-STARKs | 哈希函数安全性 |

---

## 11. 参考文献

1. Schnorr, C.P. "Efficient signature generation by smart cards." Journal of Cryptology, 1991.

2. Fiat, A., Shamir, A. "How to prove yourself: Practical solutions to identification and signature problems." CRYPTO 1986.

3. Pedersen, T.P. "Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing." CRYPTO 1991.

4. Gennaro, R., Jarecki, S., Krawczyk, H., Rabin, T. "Secure Distributed Key Generation for Discrete-Log Based Cryptosystems." EUROCRYPT 1999.

5. Bünz, B., Bootle, J., Boneh, D., Poelstra, A., Wuille, P., Maxwell, G. "Bulletproofs: Short Proofs for Confidential Transactions and More." S&P 2018.

6. Groth, J. "On the Size of Pairing-based Non-interactive Arguments." EUROCRYPT 2016.

7. Ben-Sasson, E., et al. "Scalable, transparent, and post-quantum secure computational integrity." IACR Cryptology ePrint Archive, 2018.
