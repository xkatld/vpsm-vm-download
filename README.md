# 虚拟机镜像构建

使用 GitHub Actions 原生 amd64 运行器构建 Incus 虚拟机镜像，无需自建宿主机，运行器使用 Incus 7.5。

## 镜像范围

| 发行版 | 版本 |
|---|---|
| AlmaLinux | 8、9、10 |
| Alpine | 3.21、3.22、3.23、3.24 |
| CentOS Stream | 9-Stream、10-Stream |
| Debian | bookworm、trixie、forky |
| Ubuntu | jammy、noble、resolute |

以 [镜像清单](镜像.md) 为准，15 个版本、单架构 amd64，共 15 个单规格虚拟机镜像。上游使用 default，不构建容器或 lite。CentOS Stream 并非传统 CentOS，Debian forky 是开发分支。

预装 SSH，以及 `bash git unzip screen wget curl sudo nano ca-certificates`，镜像说明地址为 `vpsm91.com`。默认规格为双核、2GiB 内存、12GiB 磁盘。

## 构建与下载

唯一工作流：`.github/workflows/build-images.yml`。

- 支持手动运行、相关主分支推送和每周一协调世界时 02:43 定时构建。
- 合并请求仅执行代码检查，不构建镜像。
- 三项作业依次为代码检查与矩阵生成、镜像构建验收、产物汇总校验，最多并行三路，单路限时一百二十分钟。
- 每个规格完成构建、清理、导出、重导入及验收，通过后才上传镜像。
- 在运行页面下载产物，保留 7 天，不自动创建发行版发布。
- 产物命名形如 `ubuntu2404-amd64-kvm`，统一为元数据 `*.tar.xz` 与磁盘 `*.qcow2` 两份，必须配套保留。
- 每份产物附带 `SHA256SUMS` 与 `build-summary.json`。
- 验收报告为 `acceptance-<发行版>-<版本>-<架构>`，失败诊断为 `diagnostics-<发行版>-<版本>-<架构>`。

## 使用与安全

发布前锁定 root 密码，无公共默认密码。启动后通过控制台设置自己的凭据：

```sh
incus exec <实例名> -- passwd root
```

新流程清理账户备份、登录历史、私人 SSH 状态和临时文件；导出前移除主机密钥，停止后清空 machine-id。首次启动生成独立身份，重启保持稳定，同一镜像的两个独立实例身份互不相同。

双栈验收以内网 IPv4、IPv6 均能登录及重启后复测为准，不要求公网 IPv6。详见 [验收要求](docs/image-acceptance.md)。

## 本地测试

统一入口，输出中文逐项结果与汇总：

```sh
python3 -I scripts/run_tests.py
```

| 模块 | 分组 |
|---|---|
| `test_build_pipeline.py` | 镜像构建 |
| `test_accept_image.py` | 镜像验收 |
| `test_verify_artifacts.py` | 构建产物校验 |
| `test_vm_image.py` | 镜像元数据 |
| `test_sanitize_vm.py` | 离线净化 |
| `test_repository_config.py` | 仓库配置 |

## 维护入口

| 文件 | 用途 |
|---|---|
| `build_pipeline.py` | 统一构建入口 |
| `scripts/setup-incus.sh` | 一次性运行器初始化，不用于已有生产宿主机 |
| `scripts/accept_image.py` | 重导入、双栈、重启及克隆身份验收 |
| `scripts/verify_artifacts.py` | 汇总产物校验 |
| `scripts/vm_image.py` | 元数据与磁盘校验、导出归一化 |
| `scripts/sanitize_vm.py` | 离线清理客户机身份与凭据 |
| `scripts/run_tests.py` | 本地与流水线共用的中文测试报告运行器 |
| `docs/image-acceptance.md` | 验收标准与边界 |
| `tests/` | 模拟单元测试 |
| `镜像.md` | 单架构构建清单 |

## 已知约束

上游镜像未固定指纹，不保证重复构建完全一致。旧产物不会自动修复，功能验收不等于公网安全加固。新增清理与身份初始化流程须由对应提交的远程运行证明。
