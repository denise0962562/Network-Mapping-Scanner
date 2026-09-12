# 扫描缓存管理

扫描器会在 SQLite 状态库中保存尚未上传的任务 ID、upload ID、批次进度和扫描观察结果。
确认这些数据不再需要时，可以在扫描器停止后执行：

```sh
scanner-rs --config config.toml cache clear
```

命令默认只清除当前配置所对应服务端 origin 的 `pending_upload` 及其关联 `observation`。
扫描器 ID、运行令牌和运行时配置均保留。清理前会显示待清任务与观察结果数量，并要求确认。
非交互环境必须显式使用 `--yes`：

```sh
scanner-rs --config config.toml cache clear --yes
```

其他选项：

```sh
# 只检查，不修改状态库或旧 JSON 文件
scanner-rs cache clear --dry-run

# 清除状态库中所有服务端 origin 的待上传结果
scanner-rs cache clear --all-origins --yes

# 同时清除服务端下发的运行时配置缓存，身份仍然保留
scanner-rs cache clear --include-runtime-config --yes
```

如果 `--state-file` 指定的旧版 JSON 状态文件仍存在，成功清理 SQLite 后也会删除该活动
文件；已经迁移并以 `.migrated` 结尾的归档不是活动缓存，不会删除。

状态库使用与扫描进程同生命周期的独占锁。因此扫描器正在运行、另一个维护命令正在执行，
或两个扫描器错误地共用同一状态库时，命令会拒绝打开状态库。不要删除 `.lock` 文件来绕过
该保护；应先停止持有状态库的扫描进程。

清除缓存会永久丢弃尚未上传的扫描结果，且不会通知服务端取消任务。需要正常完成或取消任务
时，应优先让扫描器恢复连接并完成协议流程。
