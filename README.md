# MPC 钱包 3-of-5 门限方案

## 项目概述

本项目是一个基于 Spring Boot 和 Gradle 的 MPC（安全多方计算）钱包实现，使用 3-of-5 门限方案生成分布式私钥。项目采用完整的 Gennaro DKG（分布式密钥生成）算法，通过基于 Netty 的高性能 P2P 网络在 5 个节点之间进行异步通信，每个节点连接到自己的 SQLite 数据库存储密钥份额。项目提供了简洁的 RESTful API 接口，支持分布式私钥生成、任务状态查询、群公钥获取和分布式签名等核心功能。

## 功能特性

- ✅ **完整的 Gennaro DKG**：使用 Gennaro 分布式密钥生成算法，添加遮蔽多项式，提高隐私性和安全性
- ✅ **CGMMP 分布式签名**：实现完整的 CGMMP 分布式签名协议，支持两阶段签名过程
- ✅ **3-of-5 门限方案**：将私钥分割成 5 个份额，至少需要 3 个份额才能重构私钥
- ✅ **Netty 高性能 P2P 网络**：使用 Netty 实现高性能 P2P 通信，支持异步非阻塞IO
- ✅ **异步通信**：使用 CompletableFuture 实现异步操作，提高系统性能和可伸缩性
- ✅ **每个节点独立存储**：每个节点连接到自己的 SQLite 数据库存储密钥份额
- ✅ **UUID 任务标识**：使用 UUID 作为任务唯一标识，支持异步跟踪 DKG 和签名过程
- ✅ **完整的连接池管理**：实现数据库连接池，支持连接回收、验证和超时管理
- ✅ **缓存机制**：使用 Caffeine 缓存库，缓存计算结果，提高性能
- ✅ **专用线程池**：为不同类型的任务提供专用线程池，优化线程资源使用
- ✅ **简洁的 RESTful API**：提供核心 API 接口，便于集成和使用

## 技术栈

- **后端框架**：Spring Boot 3.0.0
- **构建工具**：Gradle 8.5
- **数据库**：SQLite（每个节点一个数据库）
- **数据库连接池**：自定义连接池（支持连接回收、验证和超时管理）
- **缓存库**：Caffeine
- **加密库**：Bouncy Castle
- **网络通信**：Netty 4.1.97.Final + UDP 广播（节点发现）
- **异步处理**：CompletableFuture
- **API 设计**：RESTful API + JSON 格式响应
- **日志框架**：SLF4J
- **并发工具**：ConcurrentHashMap, CountDownLatch, Atomic 变量
- **线程池**：自定义线程池管理（计算密集型、IO密集型、定时任务）

## 项目结构

```
mpc/
├── src/
│   ├── main/
│   │   ├── java/
│   │   │   └── com/
│   │   │       └── example/
│   │   │           └── mpc/
│   │   │               ├── constant/         # 常量定义
│   │   │               │   └── Constants.java      # 系统常量
│   │   │               ├── controller/       # API 控制器
│   │   │               │   ├── DkgController.java       # DKG 相关 API
│   │   │               │   └── SignController.java      # 签名相关 API
│   │   │               ├── enums/           # 枚举类
│   │   │               │   └── TaskStatus.java          # 任务状态枚举
│   │   │               ├── model/            # 数据模型
│   │   │               │   ├── KeyShare.java         # 密钥份额模型
│   │   │               │   ├── DkgTask.java          # DKG 任务模型
│   │   │               │   └── SignatureTask.java     # 签名任务模型
│   │   │               ├── service/          # 业务逻辑服务
│   │   │               │   ├── netty/            # Netty 网络服务
│   │   │               │   │   ├── ClientHandler.java      # Netty 客户端处理器
│   │   │               │   │   ├── MessageDecoder.java     # 消息解码器
│   │   │               │   │   ├── MessageEncoder.java     # 消息编码器
│   │   │               │   │   ├── NettyService.java       # Netty 服务
│   │   │               │   │   └── ServerHandler.java      # Netty 服务器处理器
│   │   │               │   ├── DatabaseService.java  # 数据库服务
│   │   │               │   ├── DkgService.java       # DKG 服务
│   │   │               │   ├── NodeService.java      # P2P 网络服务
│   │   │               │   └── SignatureService.java  # 签名服务
│   │   │               ├── util/             # 工具类
│   │   │               │   ├── CacheUtil.java          # 缓存工具
│   │   │               │   └── ThreadPoolUtil.java     # 线程池工具
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
   - 节点 1: `http://localhost:8081/api/dkg` 和 `http://localhost:8081/api/sign`
   - 节点 2: `http://localhost:8082/api/dkg` 和 `http://localhost:8082/api/sign`
   - 节点 3: `http://localhost:8083/api/dkg` 和 `http://localhost:8083/api/sign`
   - 节点 4: `http://localhost:8084/api/dkg` 和 `http://localhost:8084/api/sign`
   - 节点 5: `http://localhost:8085/api/dkg` 和 `http://localhost:8085/api/sign`

## API 文档

### DKG 相关 API

#### 1. 生成分布式私钥并返回 UUID

**请求**
- 方法：`POST`
- 路径：`/api/dkg/start`
- 参数：无

**响应**
- 成功：`200 OK`，返回任务 ID（UUID）
- 失败：`500 Internal Server Error`，返回错误信息

**示例**
```bash
curl -X POST "http://localhost:8081/api/dkg/start"
```

**响应示例**
```json
{
  "taskId": "550e8400-e29b-41d4-a716-446655440000",
  "status": "DKG process started"
}
```

#### 2. 根据 UUID 查询任务是否执行完成

**请求**
- 方法：`GET`
- 路径：`/api/dkg/status`
- 参数：`taskId`（任务 ID，UUID 格式）

**响应**
- 成功：`200 OK`，返回任务状态
- 失败：`500 Internal Server Error`，返回错误信息

**示例**
```bash
curl -X GET "http://localhost:8081/api/dkg/status?taskId=550e8400-e29b-41d4-a716-446655440000"
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

#### 3. 根据 UUID 查询群公钥

**请求**
- 方法：`GET`
- 路径：`/api/dkg/public-key`
- 参数：`taskId`（任务 ID，UUID 格式）

**响应**
- 成功：`200 OK`，返回群公钥
- 失败：`500 Internal Server Error`，返回错误信息

**示例**
```bash
curl -X GET "http://localhost:8081/api/dkg/public-key?taskId=550e8400-e29b-41d4-a716-446655440000"
```

**响应示例**
```
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
```

### 签名相关 API

#### 4. 根据群公钥对数据进行 ECDSA 签名

**请求**
- 方法：`POST`
- 路径：`/api/sign/start`
- 参数：
  - `groupPublicKey`（群公钥，Base64 编码格式）
  - `message`（要签名的数据）

**响应**
- 成功：`200 OK`，返回签名任务 ID
- 失败：`500 Internal Server Error`，返回错误信息

**示例**
```bash
curl -X POST "http://localhost:8081/api/sign/start?groupPublicKey=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...&message=Hello%20MPC%20Wallet"
```

**响应示例**
```json
{
  "signatureTaskId": "550e8400-e29b-41d4-a716-446655440000",
  "groupPublicKey": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...",
  "message": "Hello MPC Wallet",
  "status": "Signature process started"
}
```

#### 5. 查询签名任务是否完成

**请求**
- 方法：`GET`
- 路径：`/api/sign/status`
- 参数：`signatureTaskId`（签名任务 ID，UUID 格式）

**响应**
- 成功：`200 OK`，返回签名任务状态
- 失败：`500 Internal Server Error`，返回错误信息

**示例**
```bash
curl -X GET "http://localhost:8081/api/sign/status?signatureTaskId=550e8400-e29b-41d4-a716-446655440000"
```

**响应示例**
```json
{
  "signatureTaskId": "550e8400-e29b-41d4-a716-446655440000",
  "status": "COMPLETED",
  "signature": "MEQCIHFPEKcoKcTRIc70un9UiZmpMGesrKv4hbzm8bQyT7bPAiBUdewlIWsr5pzc3r7Hz0x3mVAV8B+a26kbzKM9DZgX5w==",
  "verified": true
}
```

#### 6. 查询签名结果

**请求**
- 方法：`GET`
- 路径：`/api/sign/result`
- 参数：`signatureTaskId`（签名任务 ID，UUID 格式）

**响应**
- 成功：`200 OK`，返回签名结果
- 失败：`500 Internal Server Error`，返回错误信息

**示例**
```bash
curl -X GET "http://localhost:8081/api/sign/result?signatureTaskId=550e8400-e29b-41d4-a716-446655440000"
```

**响应示例**
```json
{
  "signatureTaskId": "550e8400-e29b-41d4-a716-446655440000",
  "signature": "MEQCIHFPEKcoKcTRIc70un9UiZmpMGesrKv4hbzm8bQyT7bPAiBUdewlIWsr5pzc3r7Hz0x3mVAV8B+a26kbzKM9DZgX5w==",
  "verified": true,
  "message": "Hello MPC Wallet"
}
```

## 技术实现细节

### 分布式密钥生成（DKG）过程

1. **节点发现**：通过 UDP 广播发现网络中的其他节点
2. **生成多项式**：每个节点生成一个随机多项式和一个遮蔽多项式，次数为阈值-1（2）
3. **生成验证点**：根据多项式生成两组验证点（承诺），用于验证份额的正确性
4. **广播验证点**：每个节点广播自己的验证点给其他节点
5. **验证验证点**：每个节点验证其他节点发送的验证点，确保它们在椭圆曲线上
6. **生成份额**：每个节点为其他节点生成份额（实际份额 + 遮蔽份额）
7. **发送份额**：每个节点将生成的份额发送给对应的节点
8. **验证份额**：每个节点验证其他节点发送的份额，使用 Gennaro 验证方法
9. **计算最终份额**：每个节点将收到的份额相加，得到最终份额
10. **生成公钥部分**：每个节点生成公钥部分并广播
11. **生成群公钥**：节点通过聚合所有公钥贡献生成群公钥
12. **存储密钥份额**：每个节点将最终份额存储到自己的 SQLite 数据库

### 分布式签名（CGMMP）过程

1. **生成随机数**：每个节点生成一个随机数 k_i
2. **生成临时公钥**：计算临时公钥 R_i = k_i * G
3. **广播临时公钥**：每个节点广播自己的临时公钥给其他节点
4. **计算全局临时公钥**：所有节点计算 R = ΣR_i
5. **计算消息哈希**：计算 h = H(m || R_x)
6. **生成签名份额**：每个节点计算 σ_i = k_i + s_i * h（s_i 是节点的密钥份额）
7. **广播签名份额**：每个节点广播自己的签名份额给其他节点
8. **验证签名份额**：每个节点验证其他节点发送的签名份额
9. **组合签名份额**：计算最终签名 σ = Σσ_i
10. **生成最终签名**：生成 (R, σ) 格式的签名并转换为传统 ECDSA 格式 (r, s)
11. **验证最终签名**：使用群公钥验证最终签名

### 节点间通信

1. **Netty 高性能通信**：使用 Netty 实现异步非阻塞 P2P 通信
2. **消息类型**：
   - `COMMITMENT`：验证点（承诺）
   - `SHARE`：份额
   - `PUBLIC_KEY_PART`：公钥部分
   - `SIGNATURE_SHARE`：签名份额
   - `PING`：心跳
   - `PONG`：心跳响应
3. **异步处理**：使用 CompletableFuture 实现异步消息处理
4. **错误处理**：包含完整的异常处理和错误恢复机制
5. **消息编解码**：使用自定义的消息编解码器，确保消息正确传输

### 性能优化

1. **缓存机制**：使用 Caffeine 缓存库，缓存椭圆曲线点计算、多项式计算和签名验证结果
2. **线程池优化**：为不同类型的任务提供专用线程池
   - 计算密集型线程池：用于密码学计算
   - IO密集型线程池：用于网络通信
   - 定时任务线程池：用于定期维护任务
3. **连接池管理**：实现完整的数据库连接池，支持：
   - 连接复用
   - 连接验证
   - 超时管理
   - 最小/最大连接数控制
4. **网络优化**：使用 Netty 实现高性能网络通信，支持异步非阻塞 IO

### 安全考虑

1. **Gennaro 承诺方案**：使用遮蔽多项式，提高隐私性和安全性
2. **CGMMP 签名协议**：实现完整的分布式签名流程，确保签名的安全性
3. **P2P 通信**：节点之间直接通信，减少中央节点风险
4. **密钥份额分离**：每个节点存储自己的密钥份额，降低单点泄露风险
5. **门限方案**：至少需要 3 个节点参与才能重构私钥
6. **验证机制**：
   - 验证点验证：确保验证点在椭圆曲线上
   - 份额验证：确保收到的份额正确
   - 签名份额验证：确保签名份额正确
   - 最终签名验证：确保最终签名有效
7. **异步处理**：减少阻塞，提高系统稳定性
8. **日志安全**：使用 SLF4J 记录日志，避免敏感信息泄露
9. **网络安全**：建议在生产环境中使用加密通信（如 TLS）

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