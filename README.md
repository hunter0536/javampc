# MPC 钱包 3-of-5 门限方案

## 项目概述

本项目是一个基于 Spring Boot 和 Gradle 的 MPC（安全多方计算）钱包实现，使用 3-of-5 门限方案生成分布式私钥。项目采用完整的 Gennaro DKG（分布式密钥生成）算法和 CGGMP 协议，通过基于 Netty 的高性能 P2P 网络在 5 个节点之间进行异步通信，每个节点连接到自己的 SQLite 数据库存储密钥份额。项目提供了简洁的 RESTful API 接口，支持分布式私钥生成、任务状态查询、群公钥获取和分布式签名等核心功能。

## 功能特性

- ✅ **完整的 Gennaro DKG**：使用 Gennaro 分布式密钥生成算法，添加遮蔽多项式，提高隐私性和安全性
- ✅ **CGGMP 分布式签名**：实现完整的 CGGMP/GG20 分布式签名协议
- ✅ **CGGMP Refresh（份额刷新）**：仅更新私钥份额，群公钥不变（不重新生成 Paillier/Pedersen）
- ✅ **真正的 CGGMP DKG**：包含 Paillier 同态加密和 Pedersen 承诺的完整 CGGMP 实现
- ✅ **3-of-5 门限方案**：将私钥分割成 5 个份额，至少需要 3 个份额才能签名
- ✅ **Netty 高性能 P2P 网络**：使用 Netty 实现高性能 P2P 通信，支持异步非阻塞IO
- ✅ **TCP 性能优化**：启用 TCP_NODELAY、1MB 缓冲区、PooledByteBufAllocator
- ✅ **UDP 广播 + 静态配置**：支持 UDP 广播自动发现和静态节点配置两种方式
- ✅ **异步通信**：使用 CompletableFuture 实现异步操作，提高系统性能和可伸缩性
- ✅ **每个节点独立存储**：每个节点连接到自己的 SQLite 数据库存储密钥份额
- ✅ **UUID 任务标识**：使用 UUID 作为任务唯一标识，支持异步跟踪 DKG 和签名过程
- ✅ **统一的 RESTful 响应**：所有 API 返回统一格式的响应体
- ✅ **专用线程池**：为不同类型的任务提供专用线程池（CPU * 4），优化线程资源使用

## 技术栈

- **后端框架**：Spring Boot 3.0.0
- **构建工具**：Gradle 8.5
- **数据库**：SQLite（每个节点一个数据库）
- **加密库**：Bouncy Castle 1.77
- **网络通信**：Netty 4.1.97.Final + UDP 广播（节点发现）
- **异步处理**：CompletableFuture
- **API 设计**：RESTful API + JSON 格式响应
- **日志框架**：SLF4J
- **并发工具**：ConcurrentHashMap, CountDownLatch, Atomic 变量

## 项目结构

```
mpc/
├── src/
│   ├── main/
│   │   ├── java/
│   │   │   └── com/
│   │   │       └── example/
│   │   │           └── mpc/
│   │   │               ├── cggmp/            # CGGMP 协议实现
│   │   │               │   ├── CGGMP.java
│   │   │               │   ├── Gg20Codec.java
│   │   │               │   ├── PaillierEncryption.java
│   │   │               │   └── PedersenCommitment.java
│   │   │               ├── common/           # 通用组件
│   │   │               │   ├── response/     # 响应类
│   │   │               │   │   ├── ApiResponse.java
│   │   │               │   │   ├── ResponseCode.java
│   │   │               │   │   ├── DkgTaskStartResponse.java
│   │   │               │   │   ├── DkgTaskStatusResponse.java
│   │   │               │   │   ├── SignatureTaskStartResponse.java
│   │   │               │   │   ├── SignatureTaskStatusResponse.java
│   │   │               │   │   └── SignatureResultResponse.java
│   │   │               │   └── util/         # 工具类
│   │   │               │       ├── HexUtils.java
│   │   │               │       └── ThreadPoolUtil.java
│   │   │               ├── config/           # 配置和初始化
│   │   │               │   └── ApplicationInitializer.java
│   │   │               ├── constant/         # 常量定义
│   │   │               │   └── Constants.java
│   │   │               ├── controller/       # API 控制器
│   │   │               │   ├── CggmpController.java
│   │   │               │   └── GennaroController.java
│   │   │               ├── dao/              # 数据访问层
│   │   │               │   ├── KeyShareDao.java
│   │   │               │   ├── ComplaintDao.java
│   │   │               │   └── AuxInfoDao.java
│   │   │               ├── enums/            # 枚举类
│   │   │               │   ├── MessageType.java
│   │   │               │   └── TaskStatus.java
│   │   │               ├── model/            # 数据模型
│   │   │               │   ├── CggmpDkgTask.java
│   │   │               │   ├── GennaroDkgTask.java
│   │   │               │   ├── Gg20SignatureTask.java
│   │   │               │   └── KeyShare.java
│   │   │               ├── service/          # 业务逻辑服务
│   │   │               │   ├── netty/
│   │   │               │   │   ├── ClientHandler.java
│   │   │               │   │   ├── NettyService.java
│   │   │               │   │   └── ServerHandler.java
│   │   │               │   ├── CggmpSignatureService.java
│   │   │               │   ├── DatabaseService.java
│   │   │               │   ├── GennaroDkgService.java
│   │   │               │   └── NodeService.java
│   │   │               └── MpcApplication.java
│   │   └── resources/
│   │       ├── application.yml           # 默认配置
│   │       ├── application-node1.yml     # 节点 1 配置
│   │       ├── application-node2.yml     # 节点 2 配置
│   │       ├── application-node3.yml     # 节点 3 配置
│   │       ├── application-node4.yml     # 节点 4 配置
│   │       └── application-node5.yml     # 节点 5 配置
│   └── test/
│       └── java/
│           └── com/
│               └── example/
│                   └── mpc/
│                       └── cggmp/
│                           └── CGGMPTest.java
├── databases/  # 存储各个节点的 SQLite 数据库
│   ├── share_1.db
│   ├── share_2.db
│   ├── share_3.db
│   ├── share_4.db
│   └── share_5.db
├── build.gradle
└── settings.gradle
```

## 性能优化

### 已完成的优化

1. **线程池优化**
   - 核心线程数：CPU 核心数 * 2
   - 最大线程数：CPU 核心数 * 4
   - 任务队列：LinkedBlockingQueue

2. **P2P 网络 TCP 优化**
   - 启用 TCP_NODELAY（禁用 Nagle 算法）
   - 接收/发送缓冲区：1MB
   - 使用 PooledByteBufAllocator
   - 写缓冲区水位：256KB - 1MB
   - WorkerGroup 线程数：CPU * 2

3. **重试机制优化**
   - 广播重试间隔：500ms → 4000ms（指数退避）
   - 减少不必要的重试日志

4. **超时参数优化**
   - 签名承诺超时：60 秒
   - 签名分享超时：30 秒
   - DKG 承诺超时：60 秒

5. **移除冗余验证**
   - 移除重复的 codec roundtrip 验证
   - 减少不必要的计算开销

### 性能测试结果

| 阶段 | 耗时 |
|------|------|
| Presign R1 (Commitment) | ~1秒 |
| Presign R2 (MtA Response + Proof) | ~2.7秒 |
| Presign R3 (Accumulate) | ~4秒 |
| **签名总耗时** | **约 4 秒** |

相比优化前（~24秒），性能提升约 **6 倍**。

## 安装和运行

### 前提条件

- Java 17 或更高版本
- Gradle 8.5 或更高版本

### 安装步骤

1. **克隆项目**

2. **构建项目**
   ```bash
   ./gradlew build
   ```

3. **运行 5 个节点**
   - 后台运行模式（推荐）：
   ```bash
   # 节点 1
   nohup java -jar build/libs/mpc-0.0.1-SNAPSHOT.jar --spring.profiles.active=node1 > node1.log 2>&1 &

   # 节点 2
   nohup java -jar build/libs/mpc-0.0.1-SNAPSHOT.jar --spring.profiles.active=node2 > node2.log 2>&1 &

   # 节点 3
   nohup java -jar build/libs/mpc-0.0.1-SNAPSHOT.jar --spring.profiles.active=node3 > node3.log 2>&1 &

   # 节点 4
   nohup java -jar build/libs/mpc-0.0.1-SNAPSHOT.jar --spring.profiles.active=node4 > node4.log 2>&1 &

   # 节点 5
   nohup java -jar build/libs/mpc-0.0.1-SNAPSHOT.jar --spring.profiles.active=node5 > node5.log 2>&1 &
   ```

   - 或使用前台模式（5 个终端窗口）：
   ```bash
   ./gradlew bootRunNode1
   ./gradlew bootRunNode2
   ./gradlew bootRunNode3
   ./gradlew bootRunNode4
   ./gradlew bootRunNode5
   ```

4. **访问 API**
   - 节点 1: `http://localhost:8081/api/gennaro`, `http://localhost:8081/api/cggmp`
   - 节点 2: `http://localhost:8082/api/gennaro`, `http://localhost:8082/api/cggmp`
   - 节点 3: `http://localhost:8083/api/gennaro`, `http://localhost:8083/api/cggmp`
   - 节点 4: `http://localhost:8084/api/gennaro`, `http://localhost:8084/api/cggmp`
   - 节点 5: `http://localhost:8085/api/gennaro`, `http://localhost:8085/api/cggmp`

## API 文档

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

### 响应状态码

| 状态码 | 说明 |
|--------|------|
| 200 | 成功 |
| 400 | 请求参数错误 |
| 404 | 资源未找到 |
| 500 | 服务器内部错误 |

---

### Gennaro DKG API

#### 1. 启动 DKG 任务

**请求**
- 方法：`POST`
- 路径：`/api/gennaro/dkg/start`

**示例**
```bash
curl -X POST "http://localhost:8081/api/gennaro/dkg/start"
```

**响应示例**
```json
{
  "code": 200,
  "message": "success",
  "data": {
    "taskId": "550e8400-e29b-41d4-a716-446655440000",
    "status": "DKG process started"
  },
  "success": true
}
```

#### 2. 查询 DKG 任务状态

**请求**
- 方法：`GET`
- 路径：`/api/gennaro/dkg/status`
- 参数：`taskId`（任务 ID）

**示例**
```bash
curl -X GET "http://localhost:8081/api/gennaro/dkg/status?taskId=550e8400-e29b-41d4-a716-446655440000"
```

**响应示例**
```json
{
  "code": 200,
  "message": "success",
  "data": {
    "taskId": "550e8400-e29b-41d4-a716-446655440000",
    "status": "COMPLETED",
    "inProgress": false,
    "completed": true,
    "groupPublicKey": "04a1b2c3...",
    "errorMessage": null,
    "receivedCommitments": 4,
    "receivedShares": 4
  },
  "success": true
}
```

#### 3. 获取群公钥

**请求**
- 方法：`GET`
- 路径：`/api/gennaro/dkg/public-key`
- 参数：`taskId`（任务 ID）

**示例**
```bash
curl -X GET "http://localhost:8081/api/gennaro/dkg/public-key?taskId=550e8400-e29b-41d4-a716-446655440000"
```

**响应示例**
```json
{
  "code": 200,
  "message": "success",
  "data": "04a1b2c3d4e5f6...",
  "success": true
}
```

---

### CGGMP DKG API

#### 4. 启动 CGGMP DKG 任务

**请求**
- 方法：`POST`
- 路径：`/api/cggmp/dkg/start`

**示例**
```bash
curl -X POST "http://localhost:8081/api/cggmp/dkg/start"
```

**响应示例**
```json
{
  "code": 200,
  "message": "success",
  "data": {
    "taskId": "550e8400-e29b-41d4-a716-446655440000",
    "status": "CGGMP DKG process started"
  },
  "success": true
}
```

#### 5. 查询 CGGMP DKG 任务状态

**请求**
- 方法：`GET`
- 路径：`/api/cggmp/dkg/status`
- 参数：`taskId`（任务 ID）

**示例**
```bash
curl -X GET "http://localhost:8081/api/cggmp/dkg/status?taskId=550e8400-e29b-41d4-a716-446655440000"
```

**响应示例**
```json
{
  "code": 200,
  "message": "success",
  "data": {
    "taskId": "550e8400-e29b-41d4-a716-446655440000",
    "status": "COMPLETED",
    "inProgress": false,
    "completed": true,
    "groupPublicKey": "04a1b2c3...",
    "errorMessage": null,
    "receivedRound1": 4,
    "receivedRound2": 4
  },
  "success": true
}
```

#### 6. 获取 CGGMP 群公钥

**请求**
- 方法：`GET`
- 路径：`/api/cggmp/dkg/public-key`
- 参数：`taskId`（任务 ID）

**示例**
```bash
curl -X GET "http://localhost:8081/api/cggmp/dkg/public-key?taskId=550e8400-e29b-41d4-a716-446655440000"
```

---

### CGGMP 签名 API

#### 7. 启动签名任务

**请求**
- 方法：`POST`
- 路径：`/api/cggmp/sign/start`
- 参数：
  - `groupPublicKey`（群公钥，Hex 编码）
  - `message`（要签名的数据）

**示例**
```bash
curl -X POST "http://localhost:8081/api/cggmp/sign/start?groupPublicKey=04a1b2c3...&message=Hello%20MPC"
```

**响应示例**
```json
{
  "code": 200,
  "message": "success",
  "data": {
    "signatureTaskId": "660e8400-e29b-41d4-a716-446655440000",
    "groupPublicKey": "04a1b2c3...",
    "message": "Hello MPC",
    "status": "CGGMP signature process started"
  },
  "success": true
}
```

#### 8. 查询签名任务状态

**请求**
- 方法：`GET`
- 路径：`/api/cggmp/sign/status`
- 参数：`signatureTaskId`（签名任务 ID）

**示例**
```bash
curl -X GET "http://localhost:8081/api/cggmp/sign/status?signatureTaskId=660e8400-e29b-41d4-a716-446655440000"
```

**响应示例**
```json
{
  "code": 200,
  "message": "success",
  "data": {
    "taskId": "660e8400-e29b-41d4-a716-446655440000",
    "groupPublicKey": "04a1b2c3...",
    "inProgress": false,
    "completed": true,
    "status": "COMPLETED",
    "message": "Hello MPC",
    "errorMessage": null,
    "participants": [1, 2, 3],
    "receivedGammaCommitments": 2,
    "receivedMtaResponses": 2,
    "receivedOffline": 2,
    "receivedPartialS": 2
  },
  "success": true
}
```

#### 9. 获取签名结果

**请求**
- 方法：`GET`
- 路径：`/api/cggmp/sign/result`
- 参数：`signatureTaskId`（签名任务 ID）

**示例**
```bash
curl -X GET "http://localhost:8081/api/cggmp/sign/result?signatureTaskId=660e8400-e29b-41d4-a716-446655440000"
```

**响应示例**
```json
{
  "code": 200,
  "message": "success",
  "data": {
    "taskId": "660e8400-e29b-41d4-a716-446655440000",
    "groupPublicKey": "04a1b2c3...",
    "signature": "30440220...",
    "verified": true,
    "message": "Hello MPC"
  },
  "success": true
}
```

## 技术实现细节

### 分布式密钥生成（Gennaro DKG）过程

1. **节点发现**：通过 UDP 广播发现网络中的其他节点，或通过静态配置连接
2. **生成多项式**：每个节点生成一个随机多项式和一个遮蔽多项式
3. **生成验证点**：根据多项式生成两组验证点（承诺）
4. **广播验证点**：每个节点广播自己的验证点给其他节点
5. **生成份额**：每个节点为其他节点生成份额
6. **发送份额**：每个节点将生成的份额发送给对应的节点
7. **验证份额**：每个节点验证其他节点发送的份额
8. **计算最终份额**：每个节点将收到的份额相加，得到最终份额
9. **生成群公钥**：节点通过聚合所有公钥贡献生成群公钥
10. **存储密钥份额**：每个节点将最终份额存储到 SQLite 数据库

### CGGMP/GG20 签名过程

1. **初始化**：加载密钥份额和 Paillier 密钥
2. **Gamma 承诺**：每个节点生成并广播 Gamma 承诺
3. **MtA 协议**：执行 MtA（Multiplicative-to-Additive）协议
4. **离线计算**：计算签名所需的离线数据
5. **部分签名**：每个节点生成部分签名
6. **签名聚合**：聚合所有部分签名生成最终签名
7. **签名验证**：使用群公钥验证最终签名

### 节点间通信

**消息类型**（`MessageType` 枚举）：

| 类型 | 说明 |
|------|------|
| `COMMITMENT` | 验证点（承诺） |
| `SHARE` | 份额 |
| `PUBLIC_KEY_PART` | 公钥部分 |
| `DKG_INIT` | DKG 初始化 |
| `CGGMP_DKG_INIT` | CGGMP DKG 初始化 |
| `CGGMP_DKG_ROUND1/2` | CGGMP DKG 各轮 |
| `GG20_SIGN_INIT` | GG20 签名初始化 |
| `GG20_GAMMA_COMMITMENT` | Gamma 承诺 |
| `GG20_MTA_INIT/RESPONSE` | MtA 协议消息 |
| `GG20_OFFLINE` | 离线数据 |
| `GG20_PARTIAL_S` | 部分签名 |
| `PING/PONG` | 心跳 |

### 节点发现机制

项目支持两种节点发现方式：

| 方式 | 适用场景 | 配置 |
|------|----------|------|
| UDP 广播 | 同一局域网 | 自动发现 |
| 静态配置 | 跨网段、云环境 | `nodes.peers` 配置 |

静态配置示例：
```yaml
nodes:
  peers: 2@192.168.1.102:8082,3@192.168.1.103:8083,4@192.168.1.104:8084,5@192.168.1.105:8085
```

格式：`节点ID@主机:端口`

## 配置说明

### application.yml 主要配置

```yaml
server:
  port: 8081

node:
  id: 1
  port: 9001

discovery:
  port: 5001
  broadcast:
    ports: 5001,5002,5003,5004,5005

nodes:
  peers:  # 静态节点配置（可选）

app:
  init:
    cggmp:
      enabled: true
    legacy:
      enabled: true
```

## 扩展和定制

- **调整门限参数**：修改 `Constants.java` 中的 `THRESHOLD` 和 `NODES_COUNT`
- **支持更多曲线**：修改 `CURVE_NAME` 常量
- **增强 P2P 网络**：添加节点身份认证、TLS 加密通信
- **集成区块链**：集成 Web3j 支持 Ethereum 签名

## 故障排除

### 常见问题

1. **节点发现失败**：
   - 检查网络是否允许 UDP 广播
   - 配置静态节点 `nodes.peers`

2. **端口冲突**：
   - 修改 `application-nodeX.yml` 中的端口配置

3. **DKG 过程超时**：
   - 检查网络连接是否稳定
   - 确保所有节点都正常运行

4. **签名验证失败**：
   - 检查群公钥和签名数据格式

## 许可证

本项目采用 MIT 许可证
