# Scanner-RS 维护文档

## 项目概述

`scanner-rs` 是一个网络扫描编排器。支持扫描器注册认证、从 HTTP API 获取扫描目标、调用 masscan 发现开放端口、调用 zgrab2 执行应用层服务识别，并以 JSON 格式通过 HTTPS POST 上报结果。

- **语言**：Rust（edition 2024）
- **运行时**：tokio 异步
- **目标平台**：Linux

---

## 模块架构

```
src/
├── main.rs          # 入口、CLI、编排主循环、身份注册
├── config.rs        # TOML 配置加载/验证/回写（注释保留）
├── scan/            # 扫描流水线、阶段编排与扫描引擎适配器
│   ├── orchestrator.rs # 阶段顺序、取消传播和失败策略
│   ├── plan.rs       # 版本化扫描计划与阶段白名单校验
│   └── engines/
│       ├── masscan.rs # masscan 端口发现、进程控制与输出解析
│       └── zgrab2.rs  # zgrab2 服务识别、进程控制与 JSON 归一化
├── cache.rs         # 按任务隔离、可持久恢复的结果缓存
├── upload.rs        # 结果上报：HTTPS POST JSON
├── register.rs      # 扫描器注册：POST /api/scanner/register
├── http_client.rs   # 底层 HTTP GET / POST
├── reconnect.rs     # 连接状态与带抖动的指数退避
├── health.rs        # 运行凭据健康检查
├── sysinfo.rs       # 系统信息采集（OS/CPU/RAM/uptime）
├── types.rs         # 全部数据结构与配置类型
├── error.rs         # 统一错误类型（thiserror）
├── logging.rs       # 日志初始化（tracing）+ log_event! 宏
└── network.rs       # IPv4/IPv6 公网出口探测与共享能力状态
```

### 模块职责与接口

#### `main.rs`

编排层。负责解析 CLI、身份管理、加载配置、组装 pipeline、驱动扫描循环。

| 函数 | 说明 |
|------|------|
| `run()` | 主入口：系统信息 → 身份处理 → 配置加载 → health check / 扫描 |
| `handle_identity()` | 处理 `--id` / `--token`，执行注册 POST，触发配置回写 |
| `scan_loop()` | 循环体：领取任务 → 扫描 → 按任务缓存 → 上传；无任务时持续轮询 |
| `flush()` | 构造包含 scanner_id/task_id 的上传载荷并提交 |
| `spawn_signal_handler()` | SIGINT/SIGTERM 注册 |

#### `config.rs`

```rust
pub(crate) fn load(path: &str) -> Result<LoadedConfig, ScannerError>
```

`LoadedConfig` 持有解析后的 `AppConfig` 以及原始文件内容。所有验证规则通过后才返回成功。

```rust
impl LoadedConfig {
    pub(crate) fn save_scanner_identity(&self) -> Result<(), ScannerError>
}
```

将当前 `scanner_id` 和 `runtime_token` 写回 **当前使用的配置文件**（`--config` 指定的路径）。旧 `token` 字段会在成功注册后移除。
实现方式为重新解析原始文件内容 → 修改 `[scanner]` 段 → 序列化写回，
**原有注释、空行、键顺序全部保留**。

#### `scan/orchestrator.rs`

```rust
pub(crate) async fn run_scan(
    scanner_path: &str,
    service_detection: &ServiceDetectionConfig,
    plan: &ScanPlan,
    target: &TargetParams,
    cancel_requested: &AtomicBool,
) -> Result<ScanOutcome, ScannerError>
```

先运行 `run_masscan()` 获取开放端口；服务识别启用时，再把 TCP 端点交给 zgrab2。

任务可携带版本化 `scan_plan`。当前支持 `legacy`、`port_only` 和
`service_inventory` 三种 profile；没有 `scan_plan` 的旧服务端任务会按本地配置生成
兼容计划。计划只描述白名单阶段，不接收二进制路径或任意 CLI 参数。

心跳通过 `scan_capabilities` 上报支持的计划版本、profile 和阶段。本地关闭 zgrab2 时仅
声明 `legacy`、`port_only` 和 `port_discovery`；启用并验证 zgrab2 后才声明
`service_inventory` 与 `service_detection`，供服务端能力调度使用。

Masscan 输出行解析：
- `Discovered <port> <protocol> <ip>` → `PortObservation`
- `open <protocol> <port> <ip> <timestamp>` → 标准 masscan list 格式
- `ERROR` → 返回错误
- `COMPLETE` / `DONE_OK` → 正常结束

masscan 只有在进程退出码为 0 时才算执行成功。非零退出码会连同最多 4096 个字符的 stderr 作为扫描错误上报，任务不会上传空结果并误标为成功；退出码为 0 且没有发现开放端口仍属于合法的空结果。

masscan 始终使用机器可读的 list 输出，不启用 `--banner`。旧的 `Discovered` 行仍保留解析兼容，
但不再接收 masscan 的服务识别结果。

#### `scan/engines/zgrab2.rs`

zgrab2 使用 `multiple` 模式。扫描器把每个开放 TCP 端点编码成 `IP,,TAG,PORT`。
`TAG` 根据端口映射为 `ssh`、`http`、`https`、`tls`、`smtp`、`mysql`、`postgres`
等模块；未映射端口使用 `banner`。SMTPS、FTPS、IMAPS、POP3S、MQTTS 使用独立
TAG，但分别复用 zgrab2 的 `smtp`、`ftp`、`imap`、`pop3`、`mqtt` 模块及其隐式
TLS 参数。

- `status=success`：写入规范化 `service`，并提取可用的短 banner；
- 每个端点只保留最终服务关联的 `evidence`，不上传完整探测尝试和候选列表；
- 应用模块根级结果已经包含 `tls` 时只保存一份应用握手，HTTPS 才额外关联独立 TLS；
- 超时、拒绝或协议错误：`service` 保持为空，只保留探测次数，不保存所有失败详情；
- 详细数据超过 `max_result_bytes`：只保留状态、错误、原大小和 `truncated=true`。

已知隐式 TLS 端口优先执行应用协议：465 → SMTPS、990 → FTPS、993 → IMAPS、
995 → POP3S、8883 → MQTTS。636（LDAPS）、853（DNS over TLS）以及 989（FTPS
数据通道）目前仍只执行通用 TLS，因为扫描器尚无相应应用握手模块。自适应模式在非标准
端口只获得 TLS 时不会提前结束，而会在剩余连接预算中优先尝试安全应用协议。

若 `required=false`，zgrab2 进程启动失败或非零退出只记录警告，masscan 端口结果照常上报；
若 `required=true`，此类错误使任务按现有可重试失败流程处理。任务取消会终止当前 masscan 或
zgrab2 子进程。

#### `cache.rs`

上传批次按稳定顺序同时满足最多 500 条 observation 和序列化 JSON 不超过 8 MiB。
任何单条 observation 超过 8 MiB 会在上传前返回明确错误；正常服务详情仍受更小的
`max_result_bytes` 限制。

```rust
impl CacheManager {
    pub(crate) fn begin_task(&mut self, task_id: Uuid) -> Result
    pub(crate) fn insert(&mut self, observation: &ScanObservation) -> Result
    pub(crate) fn upload_batches(&self, scanner_id: Uuid) -> Result<Vec<ScannerResultBatchUpload>, ScannerError>
    pub(crate) fn clear(&mut self)
}
```

缓存保存类型化的 `Port` 与 `Service` observations，并按类型、IP、端口、协议、服务名和来源
生成稳定身份去重。每个任务在 `begin_task()` 时生成一次 `upload_id`，重试期间保持不变。
`upload_batches()` 每 500 条生成一批；空任务也生成一个最终空批，只有最后一批设置
`is_final=true`。缓存同时记录下一待确认批次，重试时跳过已收到成功响应的批次；若响应
丢失，则用相同批身份重试当前批。

每次开始任务、新增观察或确认批次都会先序列化状态，再通过临时文件原子改名写入
`--state-file`（默认 `./scanner-state.json`）。启动时若存在待处理状态，扫描器在领取新任务
前先恢复上传；`observed_at`、`upload_id` 和 `batch_index` 因而不会因重启改变。

### 服务端维护协作

服务端进入维护模式后停止分配新任务，并在心跳响应中携带
`task_action=finish_and_cache`。已经领取任务的 Scanner 不会终止扫描：服务端冻结任务
租约，Scanner 在本地完成扫描并把结果写入持久状态文件。服务端不可访问或仍处于维护
状态时不上传结果，每隔 `retry_after_seconds` 探测一次维护状态。

管理员手动退出维护后，Scanner 优先补传缓存结果，再恢复领取任务。服务端默认保留
24 小时补传宽限期；宽限期内任务不会分配给其他 Scanner，超期后才回收任务。

#### `upload.rs`

```rust
impl Uploader {
    pub(crate) fn new(endpoint: String, client: ServerHttpClient) -> Self
    pub(crate) async fn upload(&self, payload: &ScannerResultBatchUpload) -> Result<(), ServerError>
}
```

`upload()` 使用运行令牌作为 Bearer 凭据，顺序发送版本 2 结果批。失败时保留任务、
`upload_id` 和所有 observations；再次上传会产生相同批身份，由服务端幂等确认。

扩展加密：在 `upload()` 中加密 payload 后再发送，调用方无需改动。

#### `register.rs`

```rust
pub(crate) async fn register(
    c_server: &str,
    c_port: i64,
    verify_tls: bool,
    connect_timeout_seconds: u64,
    request_timeout_seconds: u64,
    scanner_id: &str,
    token: &str,
) -> Result<RegisterOutcome, ScannerError>
```

使用一次性注册令牌作为 Bearer 凭据，POST `{ scanner_id }` 到注册接口。成功时解析并返回 `runtime_token`；401 不保存注册令牌。

#### `sysinfo.rs`

```rust
pub(crate) fn gather() -> Result<SystemInfo, ScannerError>
```

读取 `/proc/cpuinfo`、`/proc/meminfo`、`/proc/uptime`、`/etc/os-release`，采集 OS 名称/版本、CPU 型号/核心数、内存总量、运行时间。启动时自动打印。

#### `http_client.rs`

```rust
pub(crate) async fn fetch_task(client: &ServerHttpClient, url: &str) -> Result<FetchTaskOutcome, ServerError>
```

任务领取、心跳、任务状态上报和结果上传共享一个 `reqwest::Client`。客户端统一设置建连与
全请求超时，并把网络错误和 HTTP 响应分类为可重试故障、认证拒绝、策略拒绝及任务语义
冲突。408、429 和 5xx 可重试；429 会读取 `Retry-After`。

#### `reconnect.rs`

`ConnectionState` 通过 Tokio `watch` 通道向扫描主循环发布 `Connecting`、`Online`、
`Reconnecting`、`AuthRejected` 和 `PolicyBlocked`。主循环只在 `Online` 时领取新任务。
`Backoff` 使用带抖动的指数退避，成功心跳会清零连续失败次数；所有等待都可被停止信号
打断。

### 自动重连与任务租约

服务端领取任务响应包含 `lease_expires_at_ms` 和 `lease_ttl_ms`。心跳响应对活动任务返回：

```json
{
  "lease": {
    "task_id": "019c0000-0000-7000-8000-000000000001",
    "status": "renewed",
    "expires_at_ms": 1770000000000,
    "ttl_ms": 90000
  }
}
```

- `renewed`：扫描端按 `ttl_ms` 刷新本地单调时钟截止时间；
- `lost`：立即以 `LeaseLost` 原因取消本地任务，不发送服务端取消确认，也不上传结果；
- 旧服务端不返回 `lease` 时，扫描端为兼容现有部署，将成功心跳视为按领取任务时的 TTL
  续租；
- 活动任务重连等待受 `active_task_reconnect_max_delay_seconds` 限制；等待或请求本身不能越过
  `lease_safety_margin_seconds` 定义的安全线。

任务取消原因区分为服务端主动取消、租约丢失和本地关闭，防止把断线导致的租约丢失误报为
用户取消。

#### `health.rs`

```rust
pub(crate) async fn health_check(client: &ServerHttpClient, url: &str) -> Result<(), ScannerError>
```

健康检查调用任务接口的 `dryrun=true` 模式，只验证 scanner_id 和运行令牌，不领取任务。

#### `types.rs`

所有数据结构集中定义。配置类型使用 `serde::Deserialize`，上传类型使用 `serde::Serialize`。

#### `error.rs`

```rust
pub(crate) enum ScannerError {
    Io(std::io::Error),       // 文件 I/O
    Json(serde_json::Error),   // JSON 解析
    Toml(String),              // TOML 解析
    Http(String),              // HTTP 请求失败
    Upload(String),            // 结果上传失败
    Config(String),            // 配置验证失败
    Scan(String),              // 扫描执行失败
    HealthCheck(String),       // 健康检查失败
}
```

使用 `thiserror::Error` derive。

## 网络协议自动探测

`network.rs` 先通过 UDP 套接字检查内核能否为 IPv4/IPv6 选择源地址和路由，再使用两个
独立的 `reqwest::Client` 查询公网出口地址。每个客户端先访问服务端鉴权接口，失败后再
访问对应的备用 IP 回显接口：

- IPv4 客户端绑定 `0.0.0.0`；
- IPv6 客户端绑定 `::`。

绑定未指定地址可以限制出站套接字的地址族，同时由操作系统选择具体接口地址。UDP
`connect` 只执行本地路由选择，不会发送数据包。两个地址族通过 `tokio::join!` 并行
执行，因此某个协议超时不会串行阻塞另一个协议。运行 Token 只发送给服务端接口，不会
发送给第三方或自定义备用接口。

```rust
pub(crate) struct NetworkCapabilities {
    ipv4: NetworkFamilyCapability,
    ipv6: NetworkFamilyCapability,
}
```

每个协议包含：

| 字段 | 说明 |
|---|---|
| `supported` | 配置没有禁用该协议 |
| `ready` | 内核能够为该地址族选择源地址和路由 |
| `public_ip` | API 返回的公网地址，查询失败时为空 |
| `reason` | 禁用、无可用路由或公网 IP 查询失败等原因；公网 IP 查询失败不影响 `ready` |

服务端与备用接口均支持两种响应：

```json
{"ip":"203.0.113.10"}
```

或纯文本：

```text
203.0.113.10
```

响应必须能够解析为 IP，并与当前探测地址族一致。错误原因最多保留 256 个字符。

### 生命周期

1. 普通运行启动时，在创建心跳任务前检查本机路由并完成首次并行公网 IP 查询。
2. 扫描器使用 `scanner_id` 和运行 Token 请求服务端 `/api/scanner/network/public-ip`。
3. 服务端接口失败时，再请求该地址族配置的 `probe_url`，且不携带运行 Token。
4. `SharedNetworkCapabilities` 使用 `Arc<RwLock<_>>` 在探测任务与心跳任务之间共享快照。
5. 后台任务至少每 30 秒探测一次；实际周期来自 `probe_interval_seconds`。
6. 每次心跳读取最新快照并发送给服务端。
7. 任务响应中的 `address_family` 在执行前再次与本地快照匹配。
8. 如果不匹配，扫描器立即发一次心跳刷新服务端状态，然后以可重试失败拒绝任务。

心跳中的结构：

```json
{
  "network_capabilities": {
    "ipv4": {
      "supported": true,
      "ready": true,
      "public_ip": "203.0.113.10",
      "reason": null
    },
    "ipv6": {
      "supported": true,
      "ready": false,
      "public_ip": null,
      "reason": "route_unavailable: ..."
    }
  }
}
```

### 能力边界

本机路由检查验证的是内核能否为目标地址族选择源地址和路由，不是完整扫描验收：

- 不能证明特定私网/ULA 网段存在路由；
- 不能证明防火墙允许扫描流量或返回包；
- IPv4 NAT 出口地址通常不能直接作为 masscan 的接口源地址；
- masscan 使用自己的网络栈，实际执行仍可能因接口、网关或权限失败。

因此 `public_ip` 只用于能力展示，不参与可用性调度，也不会自动传给 masscan 作为
`--adapter-ip`。受限环境可以部署内部 IP 回显接口，避免向默认第三方接口公开出口地址。

---

## 配置参考

### config.toml

```toml
[scanner]
# Target API server hostname
c_server = "example.com"
# Target API server port
c_port = 443
# Masscan packet rate
rate = 10000000
# Masscan source port
source_port = 61000
# Verify TLS certificates (set to false for self-signed certs)
verify_tls = true
# Path to masscan binary
scanner_path = "./a"
# Auto-generated scanner identity (UUIDv7) — do not edit manually
scanner_id = "019eb66c-6ac6-7530-b73f-454037448fa2"
# Runtime token — written automatically after successful one-time registration
runtime_token = ""
connect_timeout_seconds = 5
request_timeout_seconds = 15
reconnect_initial_delay_seconds = 1
reconnect_max_delay_seconds = 60
active_task_reconnect_max_delay_seconds = 10
lease_safety_margin_seconds = 10

[service_detection]
enabled = true
required = false
zgrab_path = "zgrab2"
senders = 200
server_rate_limit = 20
connect_timeout_seconds = 5
target_timeout_seconds = 15
max_result_bytes = 65536

[network]
ipv4_enabled = true
ipv6_enabled = true
ipv4_probe_url = "https://api.ipify.org?format=json"
ipv6_probe_url = "https://api6.ipify.org?format=json"
probe_interval_seconds = 300
probe_timeout_seconds = 5

[upload]
# Endpoint for scan result upload (HTTPS POST JSON)
endpoint = "https://example.com/api/scanner/result"
```

### 字段说明

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `scanner.c_server` | string | — | 目标 API 主机名 |
| `scanner.c_port` | int | — | 目标 API 端口 |
| `scanner.rate` | int | — | masscan 本地发包速率 |
| `scanner.source_port` | int | `61000` | masscan 源端口，范围 1-65535 |
| `scanner.verify_tls` | bool | `false` | 是否验证 TLS 证书 |
| `scanner.scanner_path` | string | `"./a"` | 扫描器二进制路径；也可填写能从 `PATH` 解析的命令名 |
| `scanner.scanner_id` | string | 自动生成 | UUIDv7，首次启动自动生成 |
| `scanner.runtime_token` | string | `""` | 注册成功后由程序自动写入的运行令牌 |
| `scanner.connect_timeout_seconds` | int | `5` | 建立服务端连接的超时，范围 1-60 秒 |
| `scanner.request_timeout_seconds` | int | `15` | 单次请求总超时，不小于建连超时且不超过 300 秒 |
| `scanner.reconnect_initial_delay_seconds` | int | `1` | 首次自动重连退避，范围 1-60 秒 |
| `scanner.reconnect_max_delay_seconds` | int | `60` | 空闲状态最大重连退避，不超过 600 秒 |
| `scanner.active_task_reconnect_max_delay_seconds` | int | `10` | 活动任务最大重连退避，不超过普通最大退避 |
| `scanner.lease_safety_margin_seconds` | int | `10` | 租约到期前停止未确认任务的安全窗口，范围 1-60 秒 |
| `service_detection.enabled` | bool | `false` | 是否在端口发现后运行 zgrab2 |
| `service_detection.required` | bool | `false` | zgrab2 整体失败时是否使任务失败 |
| `service_detection.zgrab_path` | string | `"zgrab2"` | zgrab2 二进制路径或 PATH 中的命令名 |
| `service_detection.senders` | int | `200` | zgrab2 并发发送协程数，范围 1-10000 |
| `service_detection.server_rate_limit` | int | `20` | 单个目标 IP 每秒连接上限，范围 1-10000 |
| `service_detection.connect_timeout_seconds` | int | `5` | 建连超时，范围 1-60 秒 |
| `service_detection.target_timeout_seconds` | int | `15` | 单目标探测总超时，不小于建连超时且不超过 300 秒 |
| `service_detection.max_result_bytes` | int | `65536` | 单服务结构化详情上限，范围 1024-1048576 字节 |
| `network.ipv4_enabled` | bool | `true` | 是否自动探测并接受 IPv4 任务 |
| `network.ipv6_enabled` | bool | `true` | 是否自动探测并接受 IPv6 任务 |
| `network.ipv4_probe_url` | string | ipify IPv4 API | 服务端接口不可用时使用的 IPv4 IP 回显接口 |
| `network.ipv6_probe_url` | string | ipify IPv6 API | 服务端接口不可用时使用的 IPv6 IP 回显接口 |
| `network.probe_interval_seconds` | int | `300` | 重新探测周期，范围 30-86400 秒 |
| `network.probe_timeout_seconds` | int | `5` | 单次连接及总请求超时，范围 1-60 秒 |
| `upload.endpoint` | string | — | 扫描结果上报地址 |

### 验证规则

| 字段 | 条件 |
|------|------|
| `scanner.c_server` | 非空 |
| `scanner.c_port` | > 0 |
| `scanner.rate` | 1-2147483647 |
| `scanner.source_port` | 1-65535 |
| `scanner.scanner_path` | 普通扫描启动时必须能解析到存在且可执行的普通文件 |
| `service_detection.zgrab_path` | enabled=true 时必须能解析到存在且可执行的普通文件 |
| `network.probe_interval_seconds` | 30-86400 |
| `network.probe_timeout_seconds` | 1-60 |
| `upload.endpoint` | 非空 |

扫描器在启动扫描循环前检查 `scanner_path`，启用服务识别时还会检查 `zgrab_path`。显式的相对路径或绝对路径会直接检查；不含目录的命令名会从 `PATH` 查找。注册、`--health-check` 和 `--get-system-info` 模式不执行扫描，因此跳过该检查。

### 配置回写（注释保留）

注册时必须同时提供 `--id` 和 `--token`。`--token` 是不落盘的一次性注册令牌；旧配置中的 `scanner.token` 不会被当作运行令牌，升级后需重新注册。只有注册成功后，程序才会将 `scanner_id` / `runtime_token` 写回当前配置文件，并移除旧 `token` 字段。写回时保留其余注释和键顺序。

---

## 命令行

```
scanner-rs [OPTIONS]

  -c, --health-check      仅执行健康检查（不扫描）
  -d, --debug             启用 DEBUG 日志
  -i, --get-system-info   打印系统信息后退出
  -f, --config <PATH>     指定配置文件路径（默认 config.toml）
      --id <UUID>         扫描器标识（UUIDv7）
      --token <TOKEN>     注册令牌
  -h, --help              显示帮助
```

---

## 扫描器注册流程

### 首次注册

```bash
scanner-rs --id "019eb66c-..." --token "sLJiUUS6..."
```

1. 从 CLI 读取 `--id` 和 `--token`
2. 使用 `Authorization: Bearer <registration_token>` POST `{ scanner_id }` 到注册接口
3. 收到响应：
   - **200** → 解析 `runtime_token`，与 id 一起写入 `config.toml` 后退出
   - **401** → 凭证无效或过期，不写入配置
   - **5xx/网络错误** → 返回失败，不覆盖现有运行凭据
4. 后续运行无需再传 `--id` / `--token`，程序自动从配置文件读取

重新注册时必须再次同时提供新的 `--id` 和一次性 `--token`。

### 普通运行

```bash
# 从 config.toml 读取已有身份，直接启动扫描
scanner-rs
```

---

## 数据流

```
┌─────────────┐ GET /api/task/apply + Bearer ┌──────────────┐
│  target API │ ◄────────────────────────── │  scanner-rs  │
│  (c_server) │ ──────── JSON ────────────► │              │
└─────────────┘                             │  ① fetch     │
                                            │  ② deserialize│
┌─────────────┐                             │  ③ masscan   │
│   masscan   │ ◄── spawn ───────────────── │              │
│   binary    │ ─── open ports ───────────► │  ④ dispatch  │
└─────────────┘                             │              │
┌─────────────┐                             │  ⑤ zgrab2    │
│   zgrab2    │ ◄── tagged targets ──────── │              │
│   binary    │ ─── JSON results ─────────► │  ⑥ normalize │
└─────────────┘                             │  ⑦ cache     │
                                            │  ⑧ payload   │
┌─────────────┐ POST /api/scanner/result   │  ⑨ upload    │
│  upload API │ ◄──── JSON ─────────────── │              │
│  (endpoint) │                             │              │
└─────────────┘                             └──────────────┘

        ┌─ 启动时 ──────────────────────────┐
        │  POST /api/scanner/register       │  ← 仅 --id + --token 时
        │  Bearer registration_token        │
        │  { scanner_id }                   │
        └────────────────────────────────────┘
```

### 数据生命周期

1. **（可选）register** — 携带 `--id --token` 时 POST 注册
2. **sysinfo** — 采集并打印系统信息
3. **fetch** — 使用运行令牌领取真实任务；404 时等待并继续轮询
4. **deserialize** — 解析 task_id、task_target 和 task_port
5. **port discovery** — masscan 仅执行 SYN/端口发现，输出 list 格式
6. **service dispatch** — 按开放端口选择 zgrab2 module tag，仅处理 TCP
7. **service detection** — zgrab2 受控并发执行应用层握手，逐行输出 JSON
8. **normalize/cache** — 分别生成 port/service observations 并进行稳定身份去重
9. **payload/upload** — 每 500 条分批上传，最终批确认后任务完成

### 上传 JSON 格式

```json
{
  "protocol_version": 2,
  "scanner_id": "019c0000-0000-7000-8000-000000000001",
  "task_id": "019c0000-0000-7000-8000-000000000002",
  "upload_id": "019c0000-0000-7000-8000-000000000003",
  "batch_index": 0,
  "is_final": true,
  "observations": [
    {
      "kind": "port",
      "ip": "192.168.1.1",
      "port": 80,
      "protocol": "tcp",
      "state": "open",
      "source": "masscan",
      "observed_at": 1787922000000
    },
    {
      "kind": "service",
      "ip": "192.168.1.1",
      "port": 80,
      "protocol": "tcp",
      "service": "http",
      "banner": "HTTP/1.1 200 OK",
      "source": "zgrab2",
      "observed_at": 1787922001000,
      "data": {
        "schema_version": 2,
        "confidence": 100,
        "selected_probe": "http",
        "attempt_count": 4,
        "selection_reason": "protocol_handshake",
        "evidence": [
          {
            "role": "application_handshake",
            "module": "http",
            "result": {
              "response": {
                "status_line": "HTTP/1.1 200 OK"
              }
            }
          }
        ]
      }
    }
  ]
}
```

---

## 构建与运行

### 前置依赖

- Rust 工具链 ≥ 1.85（edition 2024）
- masscan 二进制
- zgrab2 二进制（仅 `service_detection.enabled=true` 时需要）

### 构建

```bash
cargo build --release
```

### 运行

```bash
# 首次：注册扫描器
./target/release/scanner-rs --id "019eb66c-..." --token "reg-code"

# 后续：直接运行
./target/release/scanner-rs

# 指定配置文件
./target/release/scanner-rs --config /etc/scanner/config.toml

# 健康检查
./target/release/scanner-rs --health-check

# 系统信息
./target/release/scanner-rs --get-system-info
```

### 测试

```bash
cargo test
```

---

## 如何扩展

### 添加新扫描器（如 nuclei）

扫描流程扩展位于 `scan/orchestrator.rs`，具体工具适配器位于 `scan/engines/`：

1. 添加新的 engine，并返回对应的类型化 observation
2. 在 `run_scan()` 中按路径/类型分发

其他模块无需改动。

### 添加数据加密

改动仅限 `upload.rs`：在 `upload()` 的 `serde_json::to_string()` 与 HTTP POST 之间插入加密步骤。

### 添加新的上报渠道

替换 `upload.rs` 中的 `Uploader`，或新增 `KafkaUploader` 等结构体。`main.rs` 只需切换实例化。

### 添加新的配置项

1. 在 `types.rs` 对应 Config 结构体中加字段（`#[serde(default)]` 实现可选）
2. 在 `config.rs` 的 `validate()` 中添加验证规则
3. 在 `main.rs` 中使用新字段

---

## 信号处理

收到 SIGINT / SIGTERM 时：

1. 设置全局 `STOP` 标志
2. 当前扫描完成后不再获取新目标
3. 执行最终 `flush()` — 将缓存数据上传
4. 正常退出

---

## 日志

| 目标 | 格式 |
|------|------|
| stderr | 人类可读，含文件+行号 |
| `./logs/scanner.YYYY-MM-DD` | JSON，按日滚动 |

级别：默认 `INFO`，`--debug` 启用 `DEBUG`。如果设置了 `RUST_LOG`，其过滤规则优先于 CLI 默认级别，例如 `RUST_LOG=scanner_rs=debug scanner-rs`。

DEBUG 日志覆盖配置加载、启动模式、任务 HTTP 状态、任务上下文、心跳与服务端命令、masscan 启动参数和进程状态、masscan stderr、输出解析统计、缓存及上传状态、重试延迟和退出清理。日志不会记录注册令牌、运行令牌或 HTTP `Authorization` 头；但会包含扫描目标、端口和扫描器输出，需按敏感运维数据保护日志文件。

---

## 依赖

| crate | 用途 |
|-------|------|
| `tokio` (full) | 异步运行时 + 进程管理 + 信号处理 |
| `clap` (derive) | 命令行参数解析 |
| `serde` + `serde_json` | 序列化 / 反序列化 |
| `toml_edit` (serde) | TOML 读写（注释保留） |
| `uuid` (v7) | UUIDv7 生成 |
| `reqwest` (json) | HTTP 客户端 |
| `chrono` (serde) | 时间戳生成 |
| `tracing` + `tracing-subscriber` + `tracing-appender` | 结构化日志 |
| `thiserror` | 错误类型 derive |

不再依赖：~~`tokio-postgres`~~、~~`anyhow`~~、~~`toml`~~
