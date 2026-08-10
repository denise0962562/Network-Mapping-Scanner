# Scanner-RS 维护文档

## 项目概述

`scanner-rs` 是一个网络扫描编排器。支持扫描器注册认证、从 HTTP API 获取扫描目标、调用外部扫描器（masscan）执行端口扫描与 banner 抓取、解析输出并以 JSON 格式通过 HTTPS POST 上报结果。

- **语言**：Rust（edition 2024）
- **运行时**：tokio 异步
- **目标平台**：Linux

---

## 模块架构

```
src/
├── main.rs          # 入口、CLI、编排主循环、身份注册
├── config.rs        # TOML 配置加载/验证/回写（注释保留）
├── scanner.rs       # 扫描器调度 + Masscan 实现
├── cache.rs         # 按任务隔离的内存结果缓存
├── upload.rs        # 结果上报：HTTPS POST JSON
├── register.rs      # 扫描器注册：POST /api/scanner/register
├── http_client.rs   # 底层 HTTP GET / POST
├── health.rs        # 运行凭据健康检查
├── sysinfo.rs       # 系统信息采集（OS/CPU/RAM/uptime）
├── types.rs         # 全部数据结构与配置类型
├── error.rs         # 统一错误类型（thiserror）
└── logging.rs       # 日志初始化（tracing）+ log_event! 宏
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

#### `scanner.rs`

```rust
pub(crate) async fn run_scan(
    scanner_path: &str,
    target: &TargetParams,
) -> Result<Vec<ScanResult>, ScannerError>
```

当前分发至 `run_masscan()`。扩展新扫描器时在此函数中增加分发逻辑。

Masscan 输出行解析：
- `Discovered <port> <protocol> <ip>` → `ScanResult { service: None, banner: None }`
- `Banner <port> <protocol> <ip> <service> <banner>` → `ScanResult { service: Some, banner: Some }`
- `ERROR` → 返回错误
- `COMPLETE` / `DONE_OK` → 正常结束

#### `cache.rs`

```rust
impl CacheManager {
    pub(crate) fn begin_task(&mut self, task_id: Uuid) -> Result
    pub(crate) fn insert(&mut self, ip, port, service, protocol, banner) -> Result
    pub(crate) fn upload_payload(&self, scanner_id: Uuid) -> Result<ScannerResultUpload, ScannerError>
    pub(crate) fn clear(&mut self)
}
```

三层聚合结构：`HashMap<IP, IpEntry { Vec<PortInfo { Vec<ServiceInfo> }> }>`

去重规则：
- 同一 IP + port + protocol 的重复 `Discovered` 行（service=None）→ 跳过
- `Banner` 行（service=Some）→ 查找首个 placeholder（name=None）填充，否则追加

缓存始终绑定一个 `task_id`。存在待上传任务时拒绝开始新任务，避免多个任务的数据混合。`upload_payload()` 将缓存转换为服务端要求的 `ScannerResultUpload`。

#### `upload.rs`

```rust
impl Uploader {
    pub(crate) fn new(endpoint: String, verify_tls: bool, runtime_token: String) -> Self
    pub(crate) async fn upload(&self, payload: &ScannerResultUpload) -> Result<(), ScannerError>
}
```

`upload()` 使用运行令牌作为 Bearer 凭据，将包含扫描器 ID、任务 ID和结果数组的 JSON 发送到 `endpoint`。失败时保留整个任务缓存并暂停领取新任务。

扩展加密：在 `upload()` 中加密 payload 后再发送，调用方无需改动。

#### `register.rs`

```rust
pub(crate) async fn register(
    c_server: &str,
    c_port: i64,
    verify_tls: bool,
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
pub(crate) async fn fetch_task(url: &str, verify_tls: bool, runtime_token: &str) -> Result<FetchTaskOutcome, ScannerError>
```

#### `health.rs`

```rust
pub(crate) async fn health_check(url: &str, verify_tls: bool, runtime_token: &str) -> Result<(), ScannerError>
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
| `upload.endpoint` | string | — | 扫描结果上报地址 |

### 验证规则

| 字段 | 条件 |
|------|------|
| `scanner.c_server` | 非空 |
| `scanner.c_port` | > 0 |
| `scanner.rate` | 1-2147483647 |
| `scanner.source_port` | 1-65535 |
| `scanner.scanner_path` | 普通扫描启动时必须能解析到存在且可执行的普通文件 |
| `upload.endpoint` | 非空 |

扫描器在启动扫描循环前检查 `scanner_path`。显式的相对路径或绝对路径会直接检查；不含目录的命令名（例如 `masscan`）会从 `PATH` 查找。注册、`--health-check` 和 `--get-system-info` 模式不执行扫描，因此跳过该检查。

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
┌─────────────┐                             │  ③ run_scan  │
│   masscan   │ ◄── spawn ───────────────── │              │
│   binary    │ ──── stdout ──────────────► │  ④ parse     │
└─────────────┘                             │  ⑤ cache     │
                                            │  ⑥ payload   │
┌─────────────┐ POST /api/scanner/result   │  ⑦ upload    │
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
5. **run_scan** — 启动 masscan 子进程，传递目标参数
6. **parse** — 逐行解析 masscan stdout（Discovered / Banner / ERROR / COMPLETE / DONE_OK）
7. **cache** — 按 IP → port → service 三层去重聚合到 `CacheManager`
8. **payload** — 生成包含 scanner_id、task_id 和 results 的载荷
9. **upload** — 携带运行令牌 HTTPS POST 到 upload endpoint

### 上传 JSON 格式

```json
{
  "scanner_id": "019c0000-0000-7000-8000-000000000001",
  "task_id": "019c0000-0000-7000-8000-000000000002",
  "results": [
    {
      "ip": "192.168.1.1",
      "port": 80,
      "protocol": "tcp",
      "service": "http",
      "banner": "Apache/2.4.29",
      "other": null
    }
  ]
}
```

---

## 构建与运行

### 前置依赖

- Rust 工具链 ≥ 1.85（edition 2024）
- masscan 二进制（或等效扫描器）

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

改动仅限 `scanner.rs`：

1. 添加 `run_nuclei(path: &str, target: &TargetParams) -> Result<Vec<ScanResult>, ScannerError>`
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

级别：默认 `INFO`，`--debug` 启用 `DEBUG`，也可通过 `RUST_LOG` 环境变量覆盖。

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
