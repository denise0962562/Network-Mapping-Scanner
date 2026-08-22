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
strategy = "adaptive"
max_probes_per_endpoint = 8
confidence_threshold = 80
zgrab_path = "zgrab2"
senders = 200
server_rate_limit = 20
connect_timeout_seconds = 5
target_timeout_seconds = 15
max_result_bytes = 65536
```

- `required = false` 时，zgrab2 整体失败仍会上报 masscan 已发现的开放端口。
- `strategy = "standard"` 保持按端口选择单个协议的旧行为；`adaptive` 先执行
  Banner、TLS 和 HTTP(S) 探测，再为未识别端点执行预算内的协议回退；`exhaustive`
  会对每个 TCP 端点执行全部受支持模块。
- 465、990、993、995 和 8883 分别使用 SMTPS、FTPS、IMAPS、POP3S 和 MQTTS
  应用握手，不会只识别成通用 TLS；非标准端口确认存在 TLS 后会优先尝试这些安全协议。
- `max_probes_per_endpoint` 限制 `adaptive` 模式对每个端点建立的探测连接数；
  `confidence_threshold` 控制写入 `service` 字段所需的最低置信度。
- service observation 只保留最终服务关联的应用握手；应用模块已经包含 TLS 时不重复保存，
  HTTPS 则额外关联一份独立 TLS 握手。未识别端点不保存全部失败详情。
- 上传批次同时限制为最多 500 条 observation 和最多 8 MiB JSON，避免少量大握手产生超大请求。
- 未配置 `[service_detection]` 的旧配置默认关闭该功能。
- zgrab2 使用系统 TCP 栈，`senders` 和 `server_rate_limit` 应从较低值开始压测，不能照搬
  masscan 的发包速率。

运行时会将结构化 JSON 日志按天写入 `./logs/scanner.log.YYYY-MM-DD`，同时保留终端输出。可以使用 `--log-directory` 指定其他目录，使用 `--debug` 将终端和文件日志级别切换为 debug：

```sh
cargo run -- --config config.toml --log-directory /var/log/network-mapping-scanner --debug
```

相对日志目录以启动扫描器时的当前工作目录为基准。程序退出时会刷新尚未写入磁盘的日志。

## 服务端自动重连

扫描器启动后会先通过心跳确认服务端可用，再开始领取任务。DNS、建连、请求超时、HTTP
408/429 和 5xx 会触发带抖动的指数退避；连接恢复并成功发送心跳后会自动恢复领取任务和
结果上传。401 表示运行令牌失效，需要重新注册；403 或其他协议错误不会无限重试。

```toml
[scanner]
connect_timeout_seconds = 5
request_timeout_seconds = 15
reconnect_initial_delay_seconds = 1
reconnect_max_delay_seconds = 60
active_task_reconnect_max_delay_seconds = 10
lease_safety_margin_seconds = 10
```

活动任务通过心跳续租。短暂断线期间本地扫描可以继续，心跳会以较短退避间隔恢复；如果
服务端明确返回租约已丢失，或扫描端在租约到期前的安全窗口仍无法确认续租，当前
masscan/zgrab2 进程会被取消，过期结果不会上传。已经生成的上传批次在租约仍有效时使用
原有 `upload_id` 和 `batch_index` 重试，因此响应丢失不会造成重复入库。

自动重连只负责当前进程生命周期内的恢复。尚未上传的结果缓存仍位于内存中，主机重启或
进程被强制终止后的持久化恢复不在本功能范围内。

## IPv4/IPv6 自动探测

扫描器启动时会分别检查 IPv4 和 IPv6 路由，并绑定对应地址族查询公网 IP，此后按配置周期
刷新。路由状态、公网出口地址和失败原因通过心跳发送给服务端，服务端只会分配当前协议
可用的任务。

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
- 扫描器优先访问服务端鉴权接口 `/api/scanner/network/public-ip`，请求携带运行 Token。
- 服务端接口不可用时回退到 `ipv4_probe_url` / `ipv6_probe_url`；备用接口不会收到运行 Token。
- 公网 IP 接口可以返回 `{"ip":"..."}`，也可以直接返回纯文本 IP。
- IPv4 探测必须返回 IPv4 地址，IPv6 探测必须返回 IPv6 地址。
- 本机无可用路由时会立即反映为该协议不可用，下个周期恢复路由后自动恢复。
- 公网 IP 接口查询失败只会使 `public_ip` 为空并记录原因，不会阻止扫描任务；该接口不是扫描链路的可用性依赖。
- 默认备用接口是第三方服务，回退时会获知扫描器出口 IP；有隐私或网络边界要求时应替换为自建接口或留空。
- 路由检查只证明操作系统能为该地址族选择源地址和路由，不代表任意私有网段都可达。

服务端下发的任务包含 `address_family`。扫描器执行前会再次检查本地最新状态；如果协议已
不可用，会先刷新心跳再拒绝任务，使服务端可以重新调度。

完整心跳格式、实现约束和故障排查参见
[扫描器维护文档](docs/MAINTENANCE.md#网络协议自动探测)。

如果需要清除编译产生的缓存，请执行

```
cargo clean
```
