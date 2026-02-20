# MPC 钱包 3-of-5 门限方案 - 实现计划

## 项目概述
创建一个基于 Spring Boot 和 Gradle 的项目，实现 MPC（安全多方计算）钱包功能，使用 3-of-5 门限方案生成分布式私钥，每个私钥份额保存在各自的 SQLite 数据库中。

## 实现计划

### [x] 任务 1: 初始化 Spring Boot Gradle 项目
- **优先级**: P0
- **Depends On**: None
- **Description**:
  - 使用 Gradle 初始化 Spring Boot 项目
  - 配置基本的项目结构和依赖管理
- **Success Criteria**:
  - 项目成功初始化，包含基本的 Spring Boot 结构
  - 能够通过 Gradle 构建项目
- **Test Requirements**:
  - `programmatic` TR-1.1: 执行 `./gradlew build` 命令成功完成
  - `human-judgement` TR-1.2: 项目结构符合 Spring Boot 标准规范

### [x] 任务 2: 配置项目依赖
- **优先级**: P0
- **Depends On**: 任务 1
- **Description**:
  - 添加必要的依赖，包括：
    - Spring Web（用于 REST API）
    - SQLite 驱动（用于数据库操作）
    - Bouncy Castle（提供密码学功能）
    - Web3j（可选，用于与以太坊交互）
    - 测试库
- **Success Criteria**:
  - 所有依赖正确配置
  - 项目能够成功构建
- **Test Requirements**:
  - `programmatic` TR-2.1: 执行 `./gradlew build` 命令成功完成
  - `human-judgement` TR-2.2: 依赖版本合理，无冲突

### [x] 任务 3: 设计数据库模型
- **优先级**: P0
- **Depends On**: 任务 2
- **Description**:
  - 设计 SQLite 数据库结构，为每个密钥份额创建独立的数据库
  - 实现数据库连接和管理功能
- **Success Criteria**:
  - 数据库模型设计合理
  - 能够成功创建和连接 SQLite 数据库
- **Test Requirements**:
  - `programmatic` TR-3.1: 数据库连接测试成功
  - `human-judgement` TR-3.2: 数据库模型设计符合最佳实践

### [x] 任务 4: 实现 3-of-5 门限 DKG 核心逻辑
- **优先级**: P1
- **Depends On**: 任务 3
- **Description**:
  - 实现 3-of-5 门限的分布式密钥生成（DKG）算法
  - 创建密钥份额管理服务
  - 实现密钥份额的安全存储到各自的 SQLite 数据库
- **Success Criteria**:
  - DKG 算法正确实现
  - 能够生成有效的 5 个密钥份额
  - 密钥份额安全存储到各自的 SQLite 数据库
- **Test Requirements**:
  - `programmatic` TR-4.1: 编写单元测试验证 DKG 算法正确性
  - `human-judgement` TR-4.2: 代码逻辑清晰，注释完善

### [x] 任务 5: 实现钱包管理服务
- **优先级**: P1
- **Depends On**: 任务 4
- **Description**:
  - 实现钱包创建和管理功能
  - 实现群公钥生成和获取
  - 确保分布式私钥生成后能够返回对应的群公钥
  - 实现钱包信息的管理
- **Success Criteria**:
  - 能够成功创建钱包
  - 能够正确生成和返回群公钥
  - 分布式私钥生成后能够返回对应的群公钥
  - 钱包信息正确管理
- **Test Requirements**:
  - `programmatic` TR-5.1: 编写单元测试验证钱包管理功能和群公钥返回
  - `human-judgement` TR-5.2: 服务设计符合业务逻辑

### [x] 任务 6: 实现 ECDSA 签名功能
- **优先级**: P1
- **Depends On**: 任务 5
- **Description**:
  - 实现基于 3-of-5 门限的 ECDSA 签名算法
  - 实现根据群公钥对数据进行签名的功能
  - 实现使用群公钥对签名结果进行验签的功能
  - 处理签名请求和验证
- **Success Criteria**:
  - 能够使用至少 3 个密钥份额对数据进行 ECDSA 签名
  - 能够根据群公钥对数据进行签名
  - 能够使用群公钥对签名结果进行验签
  - 签名结果正确有效
- **Test Requirements**:
  - `programmatic` TR-6.1: 编写单元测试验证签名功能和验签功能
  - `human-judgement` TR-6.2: 签名算法实现正确

### [x] 任务 7: 创建 REST API 端点
- **优先级**: P1
- **Depends On**: 任务 6
- **Description**:
  - 创建控制器类
  - 实现以下 API 端点：
    - 创建钱包（生成 3-of-5 门限的分布式私钥）
    - 获取钱包信息（包括群公钥）
    - 根据群公钥对数据进行签名
    - 使用群公钥对签名结果进行验签
  - 添加适当的请求参数和响应格式
- **Success Criteria**:
  - API 端点正确实现
  - 能够通过 HTTP 请求执行所有功能
  - 能够根据群公钥对数据进行签名
  - 能够使用群公钥对签名结果进行验签
- **Test Requirements**:
  - `programmatic` TR-7.1: 编写集成测试验证 API 端点，包括签名和验签功能
  - `human-judgement` TR-7.2: API 设计符合 REST 规范

### [x] 任务 8: 测试和验证
- **优先级**: P2
- **Depends On**: 任务 7
- **Description**:
  - 运行所有测试
  - 手动测试 API 端点
  - 验证所有功能正常工作
  - 测试根据群公钥对数据进行签名的功能
  - 测试使用群公钥对签名结果进行验签的功能
- **Success Criteria**:
  - 所有测试通过
  - API 端点正常工作
  - 能够成功生成 3-of-5 门限的分布式私钥
  - 密钥份额正确存储到各自的 SQLite 数据库
  - 能够使用至少 3 个密钥份额进行签名
  - 能够根据群公钥对数据进行签名
  - 能够使用群公钥对签名结果进行验签
- **Test Requirements**:
  - `programmatic` TR-8.1: 执行 `./gradlew test` 命令成功完成
  - `human-judgement` TR-8.2: 手动测试所有 API 端点，包括签名和验签功能，验证响应结果

## 技术选型

### 后端框架
- Spring Boot 3.x
- Gradle 8.x

### 数据库
- SQLite（每个密钥份额一个数据库）

### 加密库
- Bouncy Castle（提供密码学功能）
- Web3j（可选，用于与以太坊交互）

### API 设计
- RESTful API
- JSON 格式响应

## 项目结构

```
mpc/
├── src/
│   ├── main/
│   │   ├── java/
│   │   │   └── com/
│   │   │       └── example/
│   │   │           └── mpc/
│   │   │               ├── controller/
│   │   │               │   └── WalletController.java
│   │   │               ├── service/
│   │   │               │   ├── DkgService.java
│   │   │               │   ├── WalletService.java
│   │   │               │   ├── SignatureService.java
│   │   │               │   └── DatabaseService.java
│   │   │               ├── model/
│   │   │               │   ├── Wallet.java
│   │   │               │   └── KeyShare.java
│   │   │               ├── config/
│   │   │               │   └── SecurityConfig.java
│   │   │               └── MpcApplication.java
│   │   └── resources/
│   │       └── application.properties
│   └── test/
│       └── java/
│           └── com/
│               └── example/
│                   └── mpc/
│                       ├── controller/
│                       │   └── WalletControllerTest.java
│                       └── service/
│                           ├── DkgServiceTest.java
│                           └── SignatureServiceTest.java
├── databases/  # 存储各个密钥份额的 SQLite 数据库
│   ├── share_1.db
│   ├── share_2.db
│   ├── share_3.db
│   ├── share_4.db
│   └── share_5.db
├── build.gradle
└── settings.gradle
```

## 风险和注意事项

1. **安全考虑**: MPC 涉及密码学操作，需要确保实现的安全性
2. **性能优化**: DKG 算法可能计算密集，需要考虑性能优化
3. **测试覆盖**: 需要充分测试各种场景，包括边界情况
4. **依赖管理**: 确保使用的加密库版本安全可靠
5. **数据库安全**: 确保密钥份额在 SQLite 数据库中的安全存储

## 成功标准

- 项目能够成功构建和运行
- API 端点能够正确响应请求
- 能够生成有效的 3-of-5 门限分布式私钥
- 每个密钥份额正确存储到各自的 SQLite 数据库
- 分布式私钥生成后能够返回对应的群公钥
- 能够使用至少 3 个密钥份额对数据进行 ECDSA 签名
- 能够根据群公钥对数据进行签名
- 能够使用群公钥对签名结果进行验签
- 所有测试通过