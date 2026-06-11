# Scanner-RS 维护文档

## 项目概述

`scanner-rs` 是一个网络扫描编排器，从 HTTP API 获取扫描目标，调用外部扫描器（masscan）执行扫描，解析输出并以 JSON 格式通过 HTTPS POST 上报结果。

- **语言**：Rust（edition 2024）
- **运行时**：tokio 异步
- **目标平台**：Linux

---

## 模块架构

```
src/
├── main.rs          # 入口、CLI、编排主循环
├── config.rs        # TOML 配置文件加载与验证
├── scanner.rs       # 扫描器调度 + Masscan 实现
├── cache.rs         # 内存缓存：去重、聚合、打平
├── upload.rs        # 结果上报：HTTPS POST JSON
├── http_client.rs   # 底层 HTTP GET / POST
├── health.rs        # 健康检查 + 目标 JSON 验证
├── types.rs         # 全部数据结构与配置类型
├── error.rs         # 统一错误类型（thiserror）
└── logging.rs       # 日志初始化（tracing）
```

### 模块职责与接口

#### `main.rs`

编排层。负责解析 CLI、加载配置、组装 pipeline 组件、驱动扫描循环。

| 函数 | 说明 |
|------|------|
| `run()` | 主入口，按顺序执行：加载配置 → health check / 启动扫描 → 最终 flush |
| `scan_loop()` | 循环体：获取目标 → 验证 → 扫描 → 缓存 → 条件触发 flush |
| `flush()` | 调用 `cache.flatten()` → `uploader.upload()` |
| `spawn_signal_handler()` | 注册 SIGINT/SIGTERM，设置全局停止标志 |

#### `config.rs`

```rust
pub(crate) fn load_config(path: &str) -> Result<AppConfig, ScannerError>
```

读取 TOML 文件，反序列化为 `AppConfig`，逐字段验证。字段缺一不可（验证规则见表格）。

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
    pub(crate) fn insert(&mut self, ip, scanner_name, port, service, protocol, banner) -> Result
    pub(crate) fn flatten(&self) -> Vec<UploadEntry>
    pub(crate) fn clear(&mut self)
}
```

三层聚合结构：`HashMap<IP, IpEntry { Vec<PortInfo { Vec<ServiceInfo> } }> }`

去重规则：
- 同一 IP + port + protocol 的重复 `Discovered` 行（service=None）→ 跳过
- `Banner` 行（service=Some）→ 查找首个 placeholder（name=None）填充，否则追加

`flatten()` 将三层结构打平为 `Vec<UploadEntry>`，每条自包含 ip/port/protocol/scanner_name/service/banner/scan_time。

#### `upload.rs`

```rust
impl Uploader {
    pub(crate) fn new(endpoint: String, verify_tls: bool) -> Self
    pub(crate) async fn upload(&self, entries: &[UploadEntry]) -> Result<(), ScannerError>
}
```

`upload()` 将 `Vec<UploadEntry>` 序列化为 JSON，通过 HTTPS POST 发送到 `endpoint`。失败时保留缓存不清理，等待下次重试。

扩展加密：在 `upload()` 中加密 payload 后再发送，调用方无需改动。

#### `http_client.rs`

```rust
pub(crate) async fn fetch_target(url: &str, verify_tls: bool) -> Result<String, ScannerError>
pub(crate) async fn send_stop_email(...) -> Result<(), ScannerError>  // 预留
```

#### `health.rs`

```rust
pub(crate) async fn health_check(target_url: &str, verify_tls: bool) -> Result<(), ScannerError>
pub(crate) fn validate_target(json: &str, verbose: bool) -> Result<TargetParams, ScannerError>
```

验证目标 JSON 必须字段及取值范围：

| 字段 | 类型 | 范围 |
|------|------|------|
| `ip` | string | 非空 |
| `port` | string | 非空 |
| `rate` | int | (0, 1,000,000] |
| `source_port` | int | (0, 65535] |

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

使用 `thiserror::Error` derive，`Display` 和 `From` 自动生成。

---

## 配置参考

### config.toml

```toml
[scanner]
c_server = "example.com"              # 目标 API 主机
c_port = 443                          # 目标 API 端口
rate = 10000000                       # masscan 发包速率
verify_tls = false                    # 是否验证 TLS 证书（默认 false）
scanner_path = "/usr/local/bin/masscan"  # 扫描器二进制路径（默认 ./a）

[upload]
endpoint = "https://example.com/api/scan-results"  # 结果上报地址

[email_notify]
api = "api-key"
send_email = "sender@example.com"
email = "receiver@example.com"
```

### 验证规则

| 字段 | 条件 |
|------|------|
| `scanner.c_server` | 非空 |
| `scanner.c_port` | > 0 |
| `scanner.rate` | > 0 |
| `email_notify.api` | 非空 |
| `email_notify.send_email` | 非空 |
| `email_notify.email` | 非空 |
| `upload.endpoint` | 非空 |

---

## 命令行

```
scanner-rs [OPTIONS]

  -c, --health-check    仅执行健康检查（不扫描）
  -d, --debug           启用 DEBUG 日志
  -f, --config <PATH>   指定配置文件路径（默认 config.toml）
  -h, --help            显示帮助
```

---

## 数据流

```
┌─────────────┐    GET /scanner/target     ┌──────────────┐
│  target API │ ◄────────────────────────── │  scanner-rs  │
│  (c_server) │ ──────── JSON ────────────► │              │
└─────────────┘                             │  ① fetch     │
                                            │  ② validate  │
┌─────────────┐                             │  ③ run_scan  │
│   masscan   │ ◄── spawn ───────────────── │              │
│   binary    │ ──── stdout ──────────────► │  ④ parse     │
└─────────────┘                             │  ⑤ cache     │
                                            │  ⑥ flatten   │
┌─────────────┐   POST /api/scan-results   │  ⑦ upload    │
│  upload API │ ◄──── JSON ─────────────── │              │
│  (endpoint) │                             │              │
└─────────────┘                             └──────────────┘
```

### 数据生命周期

1. **fetch** — HTTP GET 从 target API 获取扫描目标 JSON
2. **validate** — 验证 JSON 字段合法性
3. **run_scan** — 启动 masscan 子进程，传递目标参数
4. **parse** — 逐行解析 masscan stdout（Discovered / Banner / ERROR / COMPLETE / DONE_OK）
5. **cache** — 按 IP → port → service 三层去重聚合到 `CacheManager`
6. **flatten** — 将缓存打平为 `Vec<UploadEntry>`
7. **upload** — HTTPS POST JSON 到 upload endpoint

### 上传 JSON 格式

```json
[
  {
    "ip": "192.168.1.1",
    "port": 80,
    "protocol": "tcp",
    "scanner_name": "masscan",
    "service": "http",
    "banner": "Apache/2.4.29",
    "scan_time": 1718123456789
  },
  {
    "ip": "192.168.1.1",
    "port": 22,
    "protocol": "tcp",
    "scanner_name": "masscan",
    "service": null,
    "banner": null,
    "scan_time": 1718123456789
  }
]
```

> `service: null` 表示端口开放但未识别服务。
> `scan_time` 为 Unix 毫秒时间戳。

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
# 默认 config.toml
./target/release/scanner-rs

# 指定配置文件
./target/release/scanner-rs --config /etc/scanner/config.toml

# 健康检查
./target/release/scanner-rs --health-check

# DEBUG 模式
./target/release/scanner-rs --debug
```

### 测试

```bash
cargo test
```

---

## 如何扩展

### 添加新扫描器（如 nuclei）

以添加漏洞扫描器为例，改动仅限 `scanner.rs`：

1. 添加 `run_nuclei(path: &str, target: &TargetParams) -> Result<Vec<ScanResult>, ScannerError>`
2. 在 `run_scan()` 中按路径/类型分发：

```rust
pub(crate) async fn run_scan(
    scanner_path: &str,
    target: &TargetParams,
) -> Result<Vec<ScanResult>, ScannerError> {
    if scanner_path.contains("nuclei") {
        return run_nuclei(scanner_path, target).await;
    }
    run_masscan(scanner_path, target).await
}
```

3. `ScanResult` 已经足够通用（ip/port/protocol/service/banner），nuclei 的漏洞信息可填入 `service` 和 `banner` 字段，或扩展 `ScanResult` 增加新字段。

其他模块无需改动。

### 添加数据加密

改动仅限 `upload.rs`：

```rust
impl Uploader {
    pub(crate) async fn upload(&self, entries: &[UploadEntry]) -> Result<(), ScannerError> {
        let mut payload = serde_json::to_string(entries)?;
        // 加密 payload
        payload = encrypt(&payload, &self.encryption_key)?;
        // ... 其余不变
    }
}
```

在 `Uploader::new()` 中增加 `encryption_key` 参数即可。`main.rs`、`cache.rs` 无需改动。

### 添加新的上报渠道

替换 `upload.rs` 中的 `Uploader`，或新增 `TcpUploader`、`KafkaUploader` 等结构体。`main.rs` 只需切换实例化：

```rust
let uploader = KafkaUploader::new(brokers, topic);
```

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

日志同时输出到：
- **stderr**（控制台，人类可读格式）
- **`./logs/scanner.YYYY-MM-DD`**（JSON 格式，按日滚动）

日志级别：
- 默认 `INFO`
- `--debug` 启用 `DEBUG`

---

## 依赖

| crate | 用途 |
|-------|------|
| `tokio` (full) | 异步运行时 + 进程管理 + 信号处理 |
| `clap` (derive) | 命令行参数解析 |
| `serde` + `serde_json` | 序列化 / 反序列化 |
| `toml` | TOML 配置文件解析 |
| `reqwest` (json, multipart) | HTTP 客户端 |
| `chrono` (serde) | 时间戳生成 |
| `tracing` + `tracing-subscriber` + `tracing-appender` | 结构化日志 |
| `thiserror` | 错误类型 derive |

不再依赖：~~`tokio-postgres`~~、~~`anyhow`~~
