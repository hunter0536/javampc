# MPC 钱包 3-of-5 门限方案

## 项目概述

本项目是一个基于 Spring Boot 和 Gradle 的 MPC（安全多方计算）钱包实现，使用 3-of-5 门限方案生成分布式私钥。项目采用完整的
Gennaro DKG（分布式密钥生成）算法和 CGGMP 协议，通过基于 Netty 的高性能 P2P 网络在 5 个节点之间进行异步通信，每个节点连接到自己的
SQLite 数据库存储密钥份额。项目提供了简洁的 RESTful API 接口，支持分布式私钥生成、任务状态查询、群公钥获取和分布式签名等核心功能。

## 功能特性

- **完整的 Gennaro DKG**：使用 Gennaro 分布式密钥生成算法，添加遮蔽多项式，提高隐私性和安全性
- **完整的 CGGMP DKG**：实现完整的 CGGMP 分布式密钥生成协议，包含 Paillier 同态加密和 Pedersen 承诺
- **CGGMP 分布式签名**：实现完整的 CGGMP 分布式签名协议
- **CGGMP Refresh（份额刷新）**：仅更新私钥份额，群公钥不变
- **3-of-5 门限方案**：将私钥分割成 5 个份额，至少需要 3 个份额才能签名
- **Netty 高性能 P2P 网络**：使用 Netty 实现高性能 P2P 通信，支持异步非阻塞IO
- **UDP 广播 + 静态配置**：支持 UDP 广播自动发现和静态节点配置两种方式
- **每个节点独立存储**：每个节点连接到自己的 SQLite 数据库存储密钥份额
- **零知识证明**：实现多种零知识证明，包括 Paillier 范围证明、BiPrime 证明等
- **预签名机制**：支持 CGGMP 预签名流程，提高签名性能
- **GMP 加速**：支持 GMP 本地库加速大整数运算

## API 接口

### 统一响应格式

所有 API 返回统一的响应格式：

```json
{
  "code": 200,
  "message": "success",
  "data": { ... },
  "success": true
}
```

---

## CGGMP 接口

### 1. AUX 接口

#### 1.1 启动 AUX 任务

生成 Paillier 公钥和 Pedersen 参数。

```bash
curl -X GET "http://localhost:8081/api/cggmp/aux/start"
```

#### 1.2 查询 AUX 任务状态

```bash
curl -X POST "http://localhost:8081/api/cggmp/aux/status" \
  -H "Content-Type: application/json" \
  -d '{"taskId": "550e8400-e29b-41d4-a716-446655440000"}'
```

---

### 2. DKG 接口

#### 2.1 启动 DKG 任务

生成分布式密钥对。

```bash
curl -X GET "http://localhost:8081/api/cggmp/dkg/start"
```

#### 2.2 查询 DKG 任务状态

```bash
curl -X POST "http://localhost:8081/api/cggmp/dkg/status" \
  -H "Content-Type: application/json" \
  -d '{"taskId": "550e8400-e29b-41d4-a716-446655440000"}'
```

#### 2.3 获取聚合公钥

```bash
curl -X POST "http://localhost:8081/api/cggmp/dkg/public-key" \
  -H "Content-Type: application/json" \
  -d '{"taskId": "550e8400-e29b-41d4-a716-446655440000"}'
```

---

### 3. Sign 接口

#### 3.1 启动签名任务

```bash
curl -X POST "http://localhost:8081/api/cggmp/sign/start" \
  -H "Content-Type: application/json" \
  -d '{
    "groupPublicKey": "04a1b2c3d4e5f6...",
    "message": "48656c6c6f"
  }'
```

#### 3.2 查询签名任务状态

```bash
curl -X POST "http://localhost:8081/api/cggmp/sign/status" \
  -H "Content-Type: application/json" \
  -d '{"signatureTaskId": "660e8400-e29b-41d4-a716-446655440000"}'
```

#### 3.3 获取签名结果

```bash
curl -X POST "http://localhost:8081/api/cggmp/sign/result" \
  -H "Content-Type: application/json" \
  -d '{"signatureTaskId": "660e8400-e29b-41d4-a716-446655440000"}'
```

---

### 4. Refresh 接口

#### 4.1 启动密钥刷新任务

更新各节点的私钥份额，聚合公钥保持不变。

```bash
curl -X POST "http://localhost:8081/api/cggmp/refresh/start" \
  -H "Content-Type: application/json" \
  -d '{"groupPublicKey": "04a1b2c3d4e5f6..."}'
```

#### 4.2 查询刷新任务状态

```bash
curl -X POST "http://localhost:8081/api/cggmp/refresh/status" \
  -H "Content-Type: application/json" \
  -d '{"taskId": "770e8400-e29b-41d4-a716-446655440000"}'
```

---

### 5. 诊断接口

#### 5.1 零知识证明自检

```bash
curl -X GET "http://localhost:8081/api/cggmp/proof/self-check"
```

---

### 6. 投诉接口

#### 6.1 查询投诉记录

```bash
curl -X POST "http://localhost:8081/api/cggmp/complaints" \
  -H "Content-Type: application/json" \
  -d '{"limit": 10}'
```

#### 6.2 导出投诉记录（JSONL）

```bash
curl -X POST "http://localhost:8081/api/cggmp/complaints/export" \
  -H "Content-Type: application/json" \
  -d '{"limit": 100}' \
  -o complaints.jsonl
```

#### 6.3 导出投诉记录（CSV）

```bash
curl -X POST "http://localhost:8081/api/cggmp/complaints/export.csv" \
  -H "Content-Type: application/json" \
  -d '{"limit": 100}' \
  -o complaints.csv
```

---

## Gennaro DKG 接口

### 1. 启动 DKG 任务

```bash
curl -X GET "http://localhost:8081/api/gennaro/dkg/start"
```

### 2. 查询 DKG 任务状态

```bash
curl -X POST "http://localhost:8081/api/gennaro/dkg/status" \
  -H "Content-Type: application/json" \
  -d '{"taskId": "550e8400-e29b-41d4-a716-446655440000"}'
```

### 3. 获取聚合公钥

```bash
curl -X POST "http://localhost:8081/api/gennaro/dkg/public-key" \
  -H "Content-Type: application/json" \
  -d '{"taskId": "550e8400-e29b-41d4-a716-446655440000"}'
```

---

## API 汇总表

| 模块                | 方法   | 路径                                 | 说明        |
|-------------------|------|------------------------------------|-----------|
| **CGGMP AUX**     | GET  | `/api/cggmp/aux/start`             | 启动 AUX 任务 |
|                   | POST | `/api/cggmp/aux/status`            | 查询 AUX 状态 |
| **CGGMP DKG**     | GET  | `/api/cggmp/dkg/start`             | 启动 DKG 任务 |
|                   | POST | `/api/cggmp/dkg/status`            | 查询 DKG 状态 |
|                   | POST | `/api/cggmp/dkg/public-key`        | 获取聚合公钥    |
| **CGGMP Sign**    | POST | `/api/cggmp/sign/start`            | 启动签名任务    |
|                   | POST | `/api/cggmp/sign/status`           | 查询签名状态    |
|                   | POST | `/api/cggmp/sign/result`           | 获取签名结果    |
| **CGGMP Refresh** | POST | `/api/cggmp/refresh/start`         | 启动刷新任务    |
|                   | POST | `/api/cggmp/refresh/status`        | 查询刷新状态    |
| **诊断**            | GET  | `/api/cggmp/proof/self-check`      | 零知识证明自检   |
| **投诉**            | POST | `/api/cggmp/complaints`            | 查询投诉记录    |
|                   | POST | `/api/cggmp/complaints/export`     | 导出 JSONL  |
|                   | POST | `/api/cggmp/complaints/export.csv` | 导出 CSV    |
| **Gennaro DKG**   | GET  | `/api/gennaro/dkg/start`           | 启动 DKG 任务 |
|                   | POST | `/api/gennaro/dkg/status`          | 查询 DKG 状态 |
|                   | POST | `/api/gennaro/dkg/public-key`      | 获取聚合公钥    |
