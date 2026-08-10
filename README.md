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

运行时会将结构化 JSON 日志按天写入 `./logs/scanner.log.YYYY-MM-DD`，同时保留终端输出。可以使用 `--log-directory` 指定其他目录，使用 `--debug` 将终端和文件日志级别切换为 debug：

```sh
cargo run -- --config config.toml --log-directory /var/log/network-mapping-scanner --debug
```

相对日志目录以启动扫描器时的当前工作目录为基准。程序退出时会刷新尚未写入磁盘的日志。

如果需要清除编译产生的缓存，请执行

```
cargo clean
```
