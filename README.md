# Network-Mapping Scanner

## 使用方法

首先打开终端，输入以下指令：
```
git clone https://github.com/wshijiang/Network-Mapping-Scanner.git
```

然后切换目录 

```
cd Network-Mapping-Scanner
```

编译
```
cargo build --release
```

普通扫描需要同时安装 `masscan` 和 `zgrab2`。masscan 只负责发现开放端口，zgrab2
按端口映射执行 SSH、HTTP(S)、TLS、邮件、数据库等应用层握手。可在配置中关闭服务识别，
以兼容只部署 masscan 的节点：

```toml
[service_detection]
enabled = true
required = false
zgrab_path = "zgrab2"
senders = 200
server_rate_limit = 20
connect_timeout_seconds = 5
target_timeout_seconds = 15
max_result_bytes = 65536
```

- `required = false` 时，zgrab2 整体失败仍会上报 masscan 已发现的开放端口。
- 单个协议握手超时或不匹配不会抹掉端口观察，只会在 service observation 的 `data` 中记录探测状态。
- 未配置 `[service_detection]` 的旧配置默认关闭该功能。
- zgrab2 使用系统 TCP 栈，`senders` 和 `server_rate_limit` 应从较低值开始压测，不能照搬
  masscan 的发包速率。

运行时会将结构化 JSON 日志按天写入 `./logs/scanner.log.YYYY-MM-DD`，同时保留终端输出。可以使用 `--log-directory` 指定其他目录，使用 `--debug` 将终端和文件日志级别切换为 debug：

```sh
cargo run -- --config config.toml --log-directory /var/log/network-mapping-scanner --debug
```

相对日志目录以启动扫描器时的当前工作目录为基准。程序退出时会刷新尚未写入磁盘的日志。

## IPv4/IPv6 自动探测

扫描器启动时会分别绑定 IPv4 和 IPv6 发起公网 IP 探测，此后按配置周期刷新。探测结果、
公网出口地址和失败原因通过心跳发送给服务端，服务端只会分配当前协议可用的任务。

```toml
[network]
ipv4_enabled = true
ipv6_enabled = true
ipv4_probe_url = "https://api.ipify.org?format=json"
ipv6_probe_url = "https://api6.ipify.org?format=json"
probe_interval_seconds = 300
probe_timeout_seconds = 5
```

- `ipv4_enabled` / `ipv6_enabled` 可显式禁用某种协议。
- 探测 API 可以返回 `{"ip":"..."}`，也可以直接返回纯文本 IP。
- IPv4 探测必须返回 IPv4 地址，IPv6 探测必须返回 IPv6 地址。
- 单次失败会立即反映为该协议不可用，下个周期成功后自动恢复。
- 默认接口是第三方服务，会获知扫描器出口 IP；有隐私或网络边界要求时应替换为自建接口。
- 此探测证明操作系统能够通过相应协议访问 HTTPS API，不代表任意私有网段都可达。

服务端下发的任务包含 `address_family`。扫描器执行前会再次检查本地最新状态；如果协议已
不可用，会先刷新心跳再拒绝任务，使服务端可以重新调度。

完整心跳格式、实现约束和故障排查参见
[扫描器维护文档](docs/MAINTENANCE.md#网络协议自动探测)。

如果需要清除编译产生的缓存，请执行

```
cargo clean
```
