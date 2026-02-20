# MPC 钱包 3-of-5 门限方案

## 项目概述

本项目是一个基于 Spring Boot 和 Gradle 的 MPC（安全多方计算）钱包实现，使用 3-of-5 门限方案生成分布式私钥。项目采用 Feldman 风格的 DKG（分布式密钥生成）算法，通过 P2P 网络在 5 个节点之间进行异步通信，每个节点连接到自己的 SQLite 数据库存储密钥份额。项目提供了简洁的 RESTful API 接口，支持分布式私钥生成、任务状态查询和群公钥获取等核心功能。

## 功能特性

- ✅ **Feldman 风格 DKG**：使用 Feldman 分布式密钥生成算法，支持验证点（承诺）机制，提高安全性
- ✅ **3-of-5 门限方案**：将私钥分割成 5 个份额，至少需要 3 个份额才能重构私钥
- ✅ **P2P 网络通信**：节点之间通过 P2P 方式通信，无需中央服务器
- ✅ **异步通信**：使用 CompletableFuture 实现异步操作，提高系统性能和可伸缩性
- ✅ **每个节点独立存储**：每个节点连接到自己的 SQLite 数据库存储密钥份额
- ✅ **UUID 任务标识**：使用 UUID 作为任务唯一标识，支持异步跟踪 DKG 过程
- ✅ **简洁的 RESTful API**：只提供 3 个核心 API 接口，便于集成和使用

## 技术栈

- **后端框架**：Spring Boot 3.0.0
- **构建工具**：Gradle 8.5
- **数据库**：SQLite（每个节点一个数据库）
- **加密库**：Bouncy Castle
- **网络通信**：Java Socket + UDP 广播（节点发现）
- **异步处理**：CompletableFuture
- **API 设计**：RESTful API + JSON 格式响应
- **日志框架**：SLF4J

## 项目结构

```
mpc/
├── src/
│   ├── main/
│   │   ├── java/
│   │   │   └── com/
│   │   │       └── example/
│   │   │           └── mpc/
│   │   │               ├── controller/       # API 控制器
│   │   │               │   └── WalletController.java  # 钱包相关 API
│   │   │               ├── service/          # 业务逻辑服务
│   │   │               │   ├── DatabaseService.java  # 数据库服务
│   │   │               │   ├── DkgService.java       # DKG 服务
│   │   │               │   ├── NodeService.java      # P2P 网络服务
│   │   │               │   ├── SignatureService.java  # 签名服务
│   │   │               │   └── WalletService.java    # 钱包服务
│   │   │               ├── model/            # 数据模型
│   │   │               │   ├── KeyShare.java         # 密钥份额模型
│   │   │               │   └── Wallet.java           # 钱包模型
│   │   │               └── MpcApplication.java  # 应用入口
│   │   └── resources/
│   │       ├── application.properties        # 默认配置
│   │       ├── application-node1.properties  # 节点 1 配置
│   │       ├── application-node2.properties  # 节点 2 配置
│   │       ├── application-node3.properties  # 节点 3 配置
│   │       ├── application-node4.properties  # 节点 4 配置
│   │       └── application-node5.properties  # 节点 5 配置
│   └── test/
│       └── java/
│           └── com/
│               └── example/
│                   └── mpc/
├── databases/  # 存储各个节点的 SQLite 数据库
│   ├── share_1.db    # 节点 1 密钥份额
│   ├── share_2.db    # 节点 2 密钥份额
│   ├── share_3.db    # 节点 3 密钥份额
│   ├── share_4.db    # 节点 4 密钥份额
│   └── share_5.db    # 节点 5 密钥份额
├── build.gradle      # Gradle 构建配置
└── settings.gradle   # Gradle 项目设置
```

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
   - 打开 5 个终端窗口，分别运行以下命令：
   
   **终端 1（节点 1）**
   ```bash
   ./gradlew bootRunNode1
   ```
   
   **终端 2（节点 2）**
   ```bash
   ./gradlew bootRunNode2
   ```
   
   **终端 3（节点 3）**
   ```bash
   ./gradlew bootRunNode3
   ```
   
   **终端 4（节点 4）**
   ```bash
   ./gradlew bootRunNode4
   ```
   
   **终端 5（节点 5）**
   ```bash
   ./gradlew bootRunNode5
   ```

4. **访问 API**
   - 节点 1: `http://localhost:8081/api/wallet`
   - 节点 2: `http://localhost:8082/api/wallet`
   - 节点 3: `http://localhost:8083/api/wallet`
   - 节点 4: `http://localhost:8084/api/wallet`
   - 节点 5: `http://localhost:8085/api/wallet`

## API 文档

### 1. 生成分布式私钥并返回 UUID

**请求**
- 方法：`POST`
- 路径：`/api/wallet/generate-key`
- 参数：无

**响应**
- 成功：`200 OK`，返回任务 ID（UUID）
- 失败：`500 Internal Server Error`，返回错误信息

**示例**
```bash
curl -X POST "http://localhost:8081/api/wallet/generate-key" -H "Content-Type: application/json"
```

**响应示例**
```json
{
  "taskId": "550e8400-e29b-41d4-a716-446655440000",
  "status": "DKG process started"
}
```

### 2. 根据 UUID 查询任务是否执行完成

**请求**
- 方法：`GET`
- 路径：`/api/wallet/task/status`
- 参数：`taskId`（任务 ID，UUID 格式）

**响应**
- 成功：`200 OK`，返回任务状态
- 失败：`500 Internal Server Error`，返回错误信息

**示例**
```bash
curl -X GET "http://localhost:8081/api/wallet/task/status?taskId=550e8400-e29b-41d4-a716-446655440000" -H "Content-Type: application/json"
```

**响应示例**
```json
{
  "taskId": "550e8400-e29b-41d4-a716-446655440000",
  "inProgress": false,
  "completed": true,
  "groupPublicKey": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA..."
}
```

### 3. 根据 UUID 查询群公钥

**请求**
- 方法：`GET`
- 路径：`/api/wallet/task/public-key`
- 参数：`taskId`（任务 ID，UUID 格式）

**响应**
- 成功：`200 OK`，返回群公钥
- 失败：`500 Internal Server Error`，返回错误信息

**示例**
```bash
curl -X GET "http://localhost:8081/api/wallet/task/public-key?taskId=550e8400-e29b-41d4-a716-446655440000" -H "Content-Type: application/json"
```

**响应示例**
```
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
```

### 4. 根据群公钥对数据进行ECDSA签名

**请求**
- 方法：`POST`
- 路径：`/api/wallet/sign`
- 参数：
  - `taskId`（任务 ID，UUID 格式）
  - `message`（要签名的数据）

**响应**
- 成功：`200 OK`，返回签名结果（包含验签状态）
- 失败：`500 Internal Server Error`，返回错误信息

**示例**
```bash
curl -X POST "http://localhost:8081/api/wallet/sign?taskId=550e8400-e29b-41d4-a716-446655440000&message=Hello%20MPC%20Wallet" -H "Content-Type: application/json"
```

**响应示例**
```json
{
  "taskId": "550e8400-e29b-41d4-a716-446655440000",
  "signature": "MEQCIHFPEKcoKcTRIc70un9UiZmpMGesrKv4hbzm8bQyT7bPAiBUdewlIWsr5pzc3r7Hz0x3mVAV8B+a26kbzKM9DZgX5w==",
  "verified": true,
  "message": "Hello MPC Wallet",
  "groupPublicKey": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA..."
}
```

## 技术实现细节

### 分布式密钥生成（DKG）过程

1. **节点发现**：通过 UDP 广播发现网络中的其他节点
2. **生成多项式**：每个节点生成一个随机多项式，次数为阈值-1（2）
3. **生成验证点**：根据多项式生成验证点（承诺），用于验证份额的正确性
4. **广播验证点**：每个节点广播自己的验证点给其他节点
5. **验证验证点**：每个节点验证其他节点发送的验证点
6. **生成份额**：每个节点为其他节点生成份额
7. **发送份额**：每个节点将生成的份额发送给对应的节点
8. **验证份额**：每个节点验证其他节点发送的份额
9. **计算最终份额**：每个节点将收到的份额相加，得到最终份额
10. **生成公钥部分**：每个节点生成公钥部分并广播
11. **生成群公钥**：节点通过聚合生成群公钥
12. **存储密钥份额**：每个节点将最终份额存储到自己的 SQLite 数据库

### 节点间通信

1. **P2P 连接**：节点之间建立直接的 Socket 连接
2. **消息类型**：
   - `COMMITMENT`：验证点（承诺）
   - `SHARE`：份额
   - `PUBLIC_KEY_PART`：公钥部分
   - `PING`：心跳
   - `PONG`：心跳响应
3. **异步处理**：使用 CompletableFuture 实现异步消息处理
4. **错误处理**：包含完整的异常处理和错误恢复机制

### 安全考虑

1. **验证点机制**：使用 Feldman 承诺方案，确保份额的正确性
2. **P2P 通信**：节点之间直接通信，减少中央节点风险
3. **密钥份额分离**：每个节点存储自己的密钥份额，降低单点泄露风险
4. **门限方案**：至少需要 3 个节点参与才能重构私钥
5. **异步处理**：减少阻塞，提高系统稳定性
6. **日志安全**：使用 SLF4J 记录日志，避免敏感信息泄露
7. **网络安全**：建议在生产环境中使用加密通信（如 TLS）

## 部署建议

1. **开发环境**：
   - 在本地运行 5 个节点，使用默认配置
   - 直接使用嵌入式 SQLite 数据库

2. **测试环境**：
   - 在不同机器上部署节点，模拟真实网络环境
   - 使用独立的 SQLite 数据库文件

3. **生产环境**：
   - 在不同物理或虚拟机器上部署节点，确保地理分散
   - 使用加密的数据库存储方案
   - 配置防火墙，限制节点间通信端口的访问
   - 实现节点身份认证机制
   - 使用 HTTPS 保护 API 接口

## 扩展和定制

- **支持更多曲线**：可以扩展支持其他椭圆曲线，如 ed25519
- **调整门限参数**：修改 `DkgService.java` 中的 `THRESHOLD` 参数，实现其他门限方案
- **增强 P2P 网络**：添加节点身份认证、加密通信等功能
- **集成区块链**：集成 Web3j 或其他区块链 SDK，支持直接与区块链交互
- **添加监控**：实现节点健康检查、性能监控等功能
- **实现密钥轮换**：添加定期更新分布式密钥的功能

## 故障排除

### 常见问题

1. **节点发现失败**：
   - 检查网络是否允许 UDP 广播
   - 确保所有节点在同一局域网内

2. **端口冲突**：
   - 检查节点端口是否被占用
   - 修改 `application-nodeX.properties` 中的端口配置

3. **DKG 过程超时**：
   - 检查网络连接是否稳定
   - 确保所有 5 个节点都正常运行

4. **签名验证失败**：
   - 检查签名数据和签名结果是否正确
   - 确保使用了正确的编码格式

5. **数据库权限**：
   - 确保应用有足够的权限创建和修改 SQLite 数据库文件

### 日志和监控

- **日志配置**：应用使用 SLF4J 记录日志，默认输出到控制台
- **日志级别**：可以在 `application.properties` 中配置日志级别
- **监控建议**：实现节点状态监控，定期检查节点健康状况

## 许可证

本项目采用 MIT 许可证

## 联系方式

如有问题或建议，欢迎联系项目维护者
