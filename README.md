# CloudPC Console · 移动云电脑纯协议控制台

通过浏览器管理本人移动云电脑账号，执行短信/密码登录、设备查询、单次桌面连接和周期连接。使用 Python 直接处理 HTTP、ZTE CAG、ICE/TLS 与 REDQ 桌面通道，不需要启动官方客户端或加载原生 SDK。

本项目依据移动云电脑 iOS 3.6.6 样本实现，目前支持已验证的 **ZTE 云电脑**。程序要求桌面视频帧和 Windows 来宾登录状态同时确认，才计为进入系统，网页不展示远程画面，也不提供键鼠输入、剪贴板或文件传输。

**已实际进入 Windows 桌面，并对齐该样本已确认的进入系统分支；自动关机期限延长仍未验证。** 2026-10-08 已补齐能力握手阶段凭据、锁屏策略、重复登录通知、用户模式及可选 token 消息。普通连接完成15秒保持、在线上报与断开清理，解码画面确认实际 Windows 桌面。锁屏诊断没有观察到状态0，因此无人值守解锁仍需锁定会话实测。详见 [官方进入流程对齐](docs/official-entry-alignment.md) 与 [进入系统验证](docs/desktop-entry.md)。

## 功能

- 密码登录、短信登录，以及服务端要求的可信设备/双因素短信验证。
- 查询本人云电脑列表，选择 ZTE 目标，显示缓存状态和最近连接结果。
- 单次连接：刷新票据、获取新连接参数、认证主通道及显示/输入/光标通道、接收有效桌面帧并确认 Windows 登录、在线上报、保持连接、断开清理。
- 已关机目标可手动选择“开机并进入系统”，等待开机和连接参数就绪；周期运行不会自动开机。
- 会话恢复：连接准备或设备查询返回 401 时，使用已保存账号密码尝试一次续登；需要短信验证时停止并提示。
- 周期连接：间隔 1–24 小时，默认 12 小时，单次保持 5–60 秒；失败后停止。
- 网页操作日志与最近连接记录；保存账号和设置时与网络任务互斥。
- Docker Compose、独立数据卷、健康检查、停止清理和已有账号迁移。

关闭网页后后台进程继续运行。服务或容器重启后，周期连接默认关闭，需要在网页重新开启。

## 协议配置

仓库包含从移动云电脑 iOS 3.6.6 样本提取的静态协议参数，包括客户端通用的签名密钥、RSA 公私钥和 ZTE AES 密钥，以及此前验证目标的两份网关证书固定值。它们不是个人账号或登录票据，不能替代正常登录。个人账号、登录会话及含这些数据的运行日志不上传。

| 文件 | 内容 | 来源 |
| --- | --- | --- |
| `sample-profile.json` | CEM 服务地址、AccessKey、签名密钥、RSA 公私钥 | 仓库已提供；格式参考 `sample-profile.example.json` |
| `zte-sample-profile.json` | ZTE AES-128 参数密钥及语言 | 仓库已提供；格式参考 `zte-sample-profile.example.json` |
| `account.local.json` | 本人账号、稳定设备身份和目标云电脑 | 首次启动自动生成，或运行 `python cloudpc_protocol.py init` |
| `live/zte-cag-pin.local.json` | CAG 的精确请求地址和已核对证书 SHA-256 | 缺失时从 `gateway-pins/zte-cag-pin.json` 自动初始化 |
| `live/zte-ice-pin.local.json` | ICE 网关的已核对证书固定信息 | 缺失时从 `gateway-pins/zte-ice-pin.json` 自动初始化 |

克隆仓库后可直接使用提供的两个协议配置文件。模板只用于说明格式，空字符串不能完成线上认证；其他客户端版本需要核对参数，随意生成的新密钥也不能替代服务端要求的参数。RSA PEM 使用 JSON 字符串中的 `\n` 表示换行。

Docker 构建会读取仓库内的协议配置和 `gateway-pins/` 两份默认固定值并写入镜像。网页启动和命令行单次连接会自动补齐数据目录中缺失的固定文件，不覆盖已存在的文件、账号或会话；旧数据卷缺少文件时也会补齐。`live/` 中的个人运行数据和日志不会进入构建上下文。

仓库固定值只适用于此前验证的网关。目标网关或证书不同会停止连接；其他目标需使用自己独立核对的固定值，程序不会自动学习新证书来绕过校验。

`deviceUid` 与登录会话绑定，迁移时一起保留。网关或证书改变后，需要重新核对本人服务返回的信息，不能关闭证书固定验证来跳过检查。

## 本地启动

需要 Python 3.12 或更新版本。以下命令在仓库根目录执行：

```sh
git clone https://github.com/jamesu4bweems6/cloudpc-console.git
cd cloudpc-console
python -m venv .venv
```

激活虚拟环境：

```powershell
# Windows PowerShell
.\.venv\Scripts\Activate.ps1
```

```sh
# Linux / macOS
source .venv/bin/activate
```

安装依赖并启动：

```sh
python -m pip install -r requirements.txt
python -X utf8 web/server.py
```

打开 **http://127.0.0.1:8765**。也可在 PowerShell 运行 `./start-web.ps1`，通过 `-Port` 改端口、`-Python` 指定解释器。

1. 保存绑定手机号；密码登录还需填写用户名和密码。账号字段留空会保留已保存的配置。
2. 选择密码或短信登录。密码登录若触发设备验证，填写该用途的最新短信验证码。多企业账号可填写企业用户名。
3. 刷新本人设备列表，选择唯一的 ZTE 云电脑并保存。
4. 同一已验证网关的证书固定文件会自动初始化，点击“立即连接一次”。如果提示网关或证书不匹配，需要核对自己目标的固定值。已关机时使用“开机并进入系统”。只有收到有效桌面帧并完成业务上报才显示成功；确认后可按需要开启周期连接。

保存了会话不表示它当前仍有效；连接前会交换新 token。如果票据交换或连接前的设备查询返回业务码 401，会使用本地已保存的用户名、密码及稳定设备身份尝试一次密码续登，更新会话后继续当前任务；成功时周期连接继续运行。设备列表刷新也采用相同恢复流程。

仅短信登录且未保存密码时，无法无人值守续登。密码不正确、需要可信设备/双因素短信验证或企业账号选择时会停止并提示；请手动登录、完成验证后重新开启周期连接。程序不会自动发送短信，也不会重复尝试密码。桌面认证、连接上报或断开清理阶段失败仍停止，不自动重放连接。

## Docker 启动

使用 Docker Compose v2 和 Linux 容器。仓库已附带该样本的两组协议参数，执行：

```sh
docker compose up -d --build
```

在服务器本机打开 **http://127.0.0.1:8766**，其他设备使用 **http://服务器IP:8766**。默认端口避开本地 Python 服务的 8765。容器内部监听 `0.0.0.0:8765`，宿主机发布到 `0.0.0.0:8766`；网页支持宿主机端口上的IP访问，仍校验同源请求和 CSRF。使用域名时在 `.env` 设置 `CLOUDPC_PUBLIC_ORIGINS` 为实际浏览器地址，例如 `https://cloudpc.example.com`。

控制台没有独立管理密码，网络访问者可以操作账号配置和连接。请只将8766开放给自己的可信设备。

从已有验证环境迁移账号、会话和证书：先停止周期连接并等待当前操作完成；已有容器也应先停止，然后执行：

```sh
python -X utf8 docker_import.py --source /path/to/existing/protocol
```

上一步成功后再执行 `docker compose up -d`。如果就在原协议目录中操作，可省略 `--source`。迁移会覆盖目标中的同名 JSON 文件，凭据通过标准输入传递，不放进命令行；文件由容器服务用户写入。

如果已经在容器登录，只缺默认固定文件，更新源码并重建容器即可自动补齐。若需要导入其他已核对网关的固定值，可使用 `docker_import.py --pins-only --source /path/to/verified/protocol`，保留当前账号和会话。详细恢复步骤见 [DOCKER.md](DOCKER.md)。

账号、会话、设置和新连接日志保存在命名数据卷中。`docker compose down` 保留数据；**`docker compose down -v` 删除数据卷**。完整迁移、端口设置、日志、健康检查及 `docker run` 示例见 [DOCKER.md](DOCKER.md)。

## 命令行

```sh
# 创建配置；已有配置不会被覆盖
python cloudpc_protocol.py init

# 正常账号认证（交互输入验证码或未配置的密码）
python cloudpc_protocol.py sms-login --send-sms
python cloudpc_protocol.py password-login

# 查询本人设备列表，写入本地 JSON
python cloudpc_protocol.py devices
python cloudpc_protocol.py snapshot

# 连接默认 session.local.json 对应的目标，保持15秒
python connect_once.py

# 使用网页保存的会话，调整保持时间
python connect_once.py --session live/web-session.local.json --hold-seconds 20

# 当前本人目标已关机时，手动开机后进入桌面
python connect_once.py --session live/web-session.local.json --power-on

# 独立周期进程；失败退出，Ctrl+C停止
python keepalive_loop.py --session live/web-session.local.json --interval-hours 12

# 断开上报失败后的恢复，使用相同会话
python cloudpc_protocol.py close-report --session live/web-session.local.json
```

`report-probe` 是早期 HTTP 上报实验，没有建立桌面通道，不能替代 `connect_once.py`。不建议同时运行多个周期进程操作同一会话和云电脑。

## 数据与结果

默认数据目录为仓库根目录；可用 `CLOUDPC_DATA_DIR` 改为独立目录。Docker 使用 `/data`。静态协议配置始终从程序目录读取。

| 字段 | 含义 |
| --- | --- |
| `success` | 有效桌面帧与 Windows 登录状态同时确认，保持连接并完成在线/断开业务上报 |
| `systemEntryConfirmed` / `desktopSessionEntered` | 收到有效画面且 Windows 登录状态为 1；锁屏画面不满足条件 |
| `desktopDisplayReady` / `desktopFrameReceived` | 收到对应 H264 视频流的完整帧，只说明显示通道可用 |
| `guestLogonState` / `guestSessionEntered` | Windows 来宾登录状态；0 或未知值不计成功，1 才允许进入系统判定 |
| `desktopProtocolConnected` | 收到桌面主通道初始化 |
| `connectedReportAccepted` / `disconnectedReportAccepted` | 在线/断开业务上报被接受 |
| `expiryRenewalVerified` | 当前始终为 `false`，关机期限续延尚无证据 |

`live/*-connect-once/` 包含完整响应、连接参数、AD 凭据和二进制报文，仅留本地。网页状态接口过滤密码、验证码、token 和 AD 凭据；浏览器不使用 localStorage 保存它们。原始日志和会话均不应随代码发布。

停止周期连接会取消后续轮次，已经开始的操作继续完成清理。服务收到终止信号时最多等待300秒，Compose退出宽限为330秒；维护前可先在页面停止周期连接并等待当前操作完成。

## 验证范围

| 项目 | 已有结果 |
| --- | --- |
| 本人账号的短信/密码登录及票据交换 | 本机生产环境验证通过 |
| ZTE CAG、ICE/TLS、REDQ 桌面通道 | 已收到 Windows 锁屏帧；RSA2048 握手及单次登录报文已发送，Windows 解锁尚未成功 |
| 本人已关机目标开机 | 本机已验证，等待就绪后获取新连接参数 |
| 网页触发真实单次连接 | 旧版认证/画面成功记录已降级；当前严格判定通过离线检查，真实解锁未确认 |
| 离线检查 | 协议及网页检查通过，不发送真实短信或云电脑请求 |
| Docker配置及运行时适配 | YAML、数据目录、映射端口来源校验和独立本地服务已检查 |
| Docker镜像构建、启动及自动初始化 | 由GitHub Actions容器检查验证，结果见仓库Actions |
| 容器内真实云电脑连接 | 尚未验证，部署后需用本人账号确认 |
| 连续超过原始1–2天的关机续期效果 | 尚未验证 |

界面显示的桌面协议 `v1.2.260108` 与样本中的 `V1.2.260728` 尚未确认对应关系；连接返回的 `V7.24.30` 是 SPICE 服务端版本，不能代替界面版本。

协议差异和本次验证证据见 [docs/desktop-entry.md](docs/desktop-entry.md)。旧版主通道认证记录在网页中显示为“仅认证”，不再算作进入系统。

## 离线检查

测试使用运行时生成的RSA测试密钥与模拟账号，不依赖本地真实协议参数：

```sh
python -m pip install -r test-requirements.txt
python -X utf8 -m unittest test_protocol test_desktop test_guest_agent -v
python -X utf8 -m unittest discover -s web -p "test_*.py" -v
```

覆盖签名及RSA独立实现对照、密码/短信/挑战流程、票据刷新、上报清理、ZTE帧布局、分片读取、来宾令牌流控、桌面帧确认、旧版成功记录降级、敏感字段过滤、并发互斥、Host/Origin/CSRF、数据迁移、首次启动及关闭处理。

GitHub Actions另执行Docker构建和HTTP启动检查，确认两份默认固定文件自动初始化。该检查使用空账号数据卷，不登录、不发送短信或访问云电脑。

## 辅助脚本

`export_profile.py` 可从自己分析得到的 Blutter 对象池重新导出 CEM 参数，默认偏移来自本项目的 3.6.6 样本。对象池文件需要自己提供：

```sh
python export_profile.py --pool /path/to/blutter/pp.txt --output sample-profile.json
```

`inspect_zte_tls.py` 查看本人设备列表中选定目标的 CAG TLS 证书并保存固定值，不发送账号或桌面认证请求：

```sh
python inspect_zte_tls.py --help
python inspect_zte_tls.py --devices devices.local.json --machine-id YOUR_MACHINE_ID
```

脚本会先尝试正常CA验证，再观察证书。保存观察值不代表已确认网关身份，使用前应与本人服务返回的信息核对。脚本不生成ICE固定值；不同于仓库默认网关的ICE信息仍需独立核对。

## 文件结构

```text
cloudpc_protocol.py        CEM认证、签名、票据和业务接口
connect_once.py            一次真实连接与清理
zte_connection.py          新连接参数与CAG证书验证
zte_gateway_probe.py       CAG / ICE / REDQ主通道及显示/输入/光标通道
zte_guest_agent.py         来宾代理能力交换与登录状态解析
keepalive_loop.py          独立周期连接进程
live_validate.py           本地协议审计支持
web/                       网页资源、后端与离线检查
Dockerfile / compose.yaml  容器部署定义
docker_import.py           本地账号、会话及证书迁移
export_profile.py          从Blutter对象池导出CEM静态参数
inspect_zte_tls.py          查看本人目标CAG证书并保存固定值
sample-profile.json        样本CEM静态协议参数
zte-sample-profile.json     样本ZTE静态协议参数
gateway-pins/              已验证网关的默认CAG及ICE证书固定值
*.example.json             不含密钥的协议配置模板
```
