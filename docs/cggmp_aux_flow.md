# CGGMP AUX 生成流程

AUX（辅助信息）是 CGGMP 签名协议中用于 Paillier 加密的关键数据，整个流程分为以下几个阶段：

## 1. 触发方式

| 触发方式 | 说明 |
|----------|------|
| **自动触发** | Leader 节点（ID 最小的节点）定期检查，发现有节点缺少 AUX 时自动发起 |
| **手动触发** | 通过 `createAuxTask()` 和 `startAuxProcess(taskId)` 手动创建任务 |

## 2. 协议流程（4 轮交互）

### Round 1 (R1) - 承诺阶段

```
生成密钥:
  • Paillier   → p, q (大素数)
  • Pedersen   → hatN, s, t, λ
  • 随机数     → ρᵢ, uᵢ
  • PRM 证明   → 证明 Pedersen 参数有效性
```

- 计算 V_commit（所有承诺的哈希）
- 通过 RBC 广播 V_commit
- 等待收集所有节点的 V_commit

### Round 1 Echo - 确认阶段

- 计算 Echo: `H(executionId, taskId, 所有 V_commit)`
- 通过 RBC 广播 Echo 哈希
- 验证各节点的 Echo 是否匹配

### Round 2 (R2) - 揭示阶段

广播明文数据：
- Paillier 公钥
- hatN, s, t
- PRM 证明
- ρᵢ, uᵢ

接收并存储其他节点的 Pedersen 参数

### Round 3 (R3) - 证明阶段

生成零知识证明：
- **MOD 证明**: 证明 p, q 是大素数 (BiPrime)
- **FAC 证明**: 证明 p, q 无小因子 (NoSmallFactor)

验证：
- 验证 MOD 证明
- 验证针对自己的 FAC 证明

## 3. 核心数据结构

**存储内容：**
- `Paillier` 密钥：p, q, n, g
- `Pedersen` 参数：hatN, s, t
- 位长度：默认 3072 bits（Paillier），证明用 2048 bits 门槛

## 4. 关键安全机制

| 机制 | 目的 |
|------|------|
| **V_commit** | 承诺阶段防止后续篡改 |
| **Echo 阶段** | 确保所有节点收到 R1 后才揭示 |
| **PRM 证明** | 证明 Pedersen 参数由正确的 λ 生成 |
| **MOD 证明** | 证明自己的 p, q 是合法大素数（BiPrime Blum） |
| **FAC 证明** | 证明 p, q 没有小因子，防止恶意密钥 |

## 5. 代码位置

- 入口：`CggmpAuxService.runAuxProtocolAsync()`
- 消息处理：`CggmpAuxService.handleMessage()`
- 保存：`CggmpAuxService.saveAuxInfo()`

## 6. 自动触发逻辑

1. Leader 节点（ID 最小）定期检查 AUX 状态
2. 广播 `CGGMP_AUX_STATUS` 询问各节点是否有 AUX
3. 收集所有节点状态：
   - 如果有节点缺失 AUX → 发起 AUX 任务
   - 如果所有节点都有 AUX → 跳过
4.Leader 节点负责协调整个流程，其他节点被动参与
