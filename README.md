# systemd-unit-hardening-auditor

纯 Python 的 systemd 单元加固审计库。读取主 unit 与按文件名排序的 drop-in，
计算最终生效的 `User`、`Group`、`ExecStart`、`CapabilityBoundingSet`、
`ProtectSystem`、`ProtectHome`、`PrivateTmp`、`ReadWritePaths` 等取值，
再结合路径权限标出低权限用户可替换的二进制或配置。

## 不会调用 systemctl

本工具是**纯静态分析器**：

- 只读取调用方指定目录中的 unit、drop-in、preset、环境文件和文件系统元数据；
- 从不执行 `systemctl`、`systemd-analyze`、`busctl`，也不连接 service manager；
- 因此可以对一份拷贝出来的目录树（例如取证镜像、CI 工件）离线审计，
  也可以在没有 systemd 的机器或容器里运行。

## systemd 语义覆盖

合并规则严格对照 `systemd.unit(5)`、`systemd.service(5)`、`systemd.exec(5)`：

- **drop-in 顺序**：不同文件名按文件名字典序应用，与所在目录无关；
  同名文件按 `/etc > /run > /usr/lib` 优先级；实例 drop-in 先于模板 drop-in。
- **标量指令**（如 `User`、`ProtectSystem`）：最后一次赋值生效。
- **列表指令**（如 `ReadWritePaths`）：逐次追加；`Key=` 空赋值会清空之前的列表，
  报告里仍保留这次重置的文件与行号。
- **`CapabilityBoundingSet`**：普通赋值按 OR 合并，`~` 前缀按全集取反并以 AND 合并；
  空赋值重置为**空集合**，单独的 `~` 重置为完整能力集合。
- **`ProtectSystem`/`ProtectHome`/`PrivateTmp`**：布尔值与 `full`、`strict`、
  `tmpfs`、`read-only` 等特殊取值统一归一化（如 `yes` → `ProtectSystem=full`）。
- **模板实例**：`worker@edge.service` 自动回退到 `worker@.service` 主文件，
  并展开 `%n`、`%p`、`%i`、`%I`、`%%` 等 specifier。
- **环境文件**：支持 `EnvironmentFile=-/path`（缺失仅软告警）、引号、`export`，
  内联 `Environment=` 与环境文件中的变量可用于 `$VAR`/`${VAR}` 展开。
- **Exec 前缀与相对路径**：识别 `-`、`:`、`+`、`!`、`!!`、`@` 前缀；
  不带斜杠的相对命令按 `PATH`（默认 systemd 服务搜索路径）解析。
- **preset**：评估 `system-preset`/`user-preset` 中的 `enable`/`disable` 规则，
  仅用于说明默认启用策略，不影响运行时加固项。
- **mask**：主文件或 drop-in 是指向 `/dev/null` 的符号链接时给出告警。

## 路径暴露分析

对 `ExecStart*` 二进制、`EnvironmentFile` 和 `ReadWritePaths` 逐组件检查
属主、属组与 mode 位：

- `other` 写位、非 root 属组写位、非 root 属主写位都会产生发现；
- sticky 的全局可写目录（`/tmp` 风格）不视为已有 root 文件的替换向量；
- 每个发现都带目标路径、首个可写组件、主体（principal）、mode 和
  触发该分析的指令来源。

在非 root 环境下审计暂存目录树时，树内组件默认按 root 拥有处理，
也可通过 `owner_override` 显式声明非 root 属主。

## 用法

```python
from systemd_auditor import audit_unit

report = audit_unit(
    "app.service",
    search_roots=["/etc/systemd/system", "/run/systemd/system"],
)
print(report.to_text())
payload = report.to_dict()  # 结构化结果，含每条取值的生效来源
```

对一份离线拷贝做审计：

```python
report = audit_unit(
    "app@worker1.service",
    search_roots=["/staged/etc/systemd/system"],
    path_prefix="/staged",
)
```

命令行：

```bash
python -m systemd_auditor app.service \
    --root /etc/systemd/system --root /run/systemd/system
python -m systemd_auditor app.service --root /staged/etc/systemd/system \
    --path-prefix /staged --json
```

输出中的每一条最终取值和发现都指向**最终生效的文件、段与行号**，例如：

```text
ProtectSystem=off  <- /etc/systemd/system/app.service.d/override.conf:2 [Service]
```

这正是人工逐个查看时最容易误判的场景：主 unit 写着 `ProtectSystem=strict`，
但 `override.conf` 又把它改回了关闭状态，审计报告会明确标出覆盖来源。

## 测试

```bash
python -m unittest
```

测试覆盖：drop-in 覆盖与跨目录优先级、空赋值重置、模板实例与 specifier、
环境文件与变量展开、相对 Exec 路径与 PATH 解析、能力集合 OR/AND/取反/重置、
sticky 目录与 world/group 可写判定、preset 与 mask，以及 CLI/JSON 输出。
