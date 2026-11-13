# Socks-VPS

Socks-VPS 是独立Go SOCKS5服务，不引入Xray运行时。

## 运行与检查

- 安装（用户侧）：`bash <(curl -fsSL https://github.com/NovixLink/Socks-VPS/releases/latest/download/install.sh)`，管理入口 `sudo socks-vpsctl`，完整命令与免交互参数见 [README](README.md)。
- 构建：`go build ./cmd/socks-vps`，依赖用 `go.sum` 锁定。
- 测试、发布脚本和构建门禁不在公开仓库，在维护者资料里（见“资料入口”），按那里的说明运行。没有维护者资料时只能做构建和静态检查，不声称测试通过。

## 核心约束

- 仅IPv4、RFC 1929用户名/密码认证及TCP `CONNECT`；域名只查询A记录，检查后拨已批准公网IPv4，保持公开命令、JSON和退出码契约。
- 配置、端口、凭据及大陆来源开关以实例JSON为权威。手动端口保持原值；自动端口以真实bind为准。合法无操作不安装依赖、不停服、不写配置。
- 与WARP VPS Manager独立：服务、网卡、路由、配置及其nftables对象都是外部资源。生命周期只处理归属明确的Socks-VPS资源。
- CN阻断使用项目自有nftables表，不绕过主机已有策略。IPdeny数据由维护者校验后随版本包交付，VPS生命周期不另行获取IPdeny。
- 同一次修改仅暂存必要原值，不恢复持久快照、marker或第二套状态。系统适配、依赖、交互及完整生命周期合同以维护者资料中的实现偏好（`cowork/docs/systems/implementation-preferences.md`）为准。
- 公开源码和发布包各自使用精确成员清单，不为通过而放宽门禁。发布、双架构包验证与Linux实际网络验收分别记录；历史授权不作为当前执行许可。
- 凭据、测试机地址与SSH信息不进入共享文档或发布包；安装包不包含AGENTS、cowork或localwork。

## 做什么读什么

| 任务 | 读 |
|---|---|
| 安装、命令、免交互参数、用户可见行为 | [README](README.md) |
| 服务、认证、目标过滤、转发 | `cmd/socks-vps/`、`internal/` |
| 安装与生命周期脚本 | `scripts/install.sh`、`scripts/bootstrap.sh` |
| 防火墙规则 | `scripts/firewall.sh`、`internal/firewall/` |
| 服务单元 | `packaging/systemd/` |
| IPdeny 数据与版权 | `assets/ipdeny/`、[THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES.md) |
| 进度、决定、踩坑、发布与实机验收 | `cowork/`，先读 `cowork/AGENTS.md` |

## 资料入口

- 维护者内部资料在私有仓库 `NovixLink/Socks-VPS-internal`。有权限时在本仓库根目录执行 `gh repo clone NovixLink/Socks-VPS-internal cowork`；`cowork/` 已被忽略，不进入公开仓库。存在 `cowork/AGENTS.md` 时先读它。
- 无权限或尚未克隆时只按本文件和 README 工作；不在公开仓库新建 cowork 或提交内部资料。
- 本仓库只提交公开源码、规则和使用说明；内部链接与内部规则只写在 cowork。`localwork/` 只放个人本机备注，不进入Git或发布产物。
