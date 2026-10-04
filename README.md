# CloudPC Console · 移动云电脑纯协议控制台

通过浏览器管理本人移动云电脑账号，执行短信/密码登录、设备查询、单次桌面连接和周期连接。使用 Python 直接处理 HTTP、ZTE CAG、ICE/TLS 与 REDQ 主通道，不需要启动官方客户端或加载原生 SDK。

本项目依据移动云电脑 iOS 3.6.6 样本实现，目前支持已验证的 **ZTE 云电脑**。它不提供桌面画面、键鼠输入、剪贴板或文件传输。

**自动关机期限延长仍未验证。** 一次真实桌面连接及在线上报已成功，但接口和客户端均未显示关机截止时间；周期连接属于候选续期方案，不能保证云电脑始终不关机。

## 功能

- 密码登录、短信登录，以及服务端要求的可信设备/双因素短信验证。
- 查询本人云电脑列表，选择 ZTE 目标，显示缓存状态和最近连接结果。
- 单次连接：刷新票据、获取新连接参数、认证主通道、响应 PING、在线上报、保持连接、断开清理。
- 周期连接：间隔 1–12 小时，单次保持 5–60 秒；失败后停止。
- 网页操作日志与最近连接记录；保存账号和设置时与网络任务互斥。
- Docker Compose、独立数据卷、健康检查、停止清理和已有账号迁移。

关闭网页后后台进程继续运行。服务或容器重启后，周期连接默认关闭，需要在网页重新开启。

## 协议配置

公开仓库只提供配置模板，**不包含提取的私钥、签名密钥、AES 密钥、个人账号或登录票据**。联网登录和桌面连接前，需要准备与所分析客户端版本匹配的协议参数。

| 本地文件 | 内容 | 模板 |
| --- | --- | --- |
| `sample-profile.json` | CEM 服务地址、AccessKey、签名密钥、RSA 公私钥 | `sample-profile.example.json` |
| `zte-sample-profile.json` | ZTE AES-128 参数密钥及语言 | `zte-sample-profile.example.json` |
| `account.local.json` | 本人账号、稳定设备身份和目标云电脑 | 首次启动自动生成，或运行 `python cloudpc_protocol.py init` |
| `live/zte-cag-pin.local.json` | 本人 CAG 的精确请求地址和已核对证书 SHA-256 | 由已有验证环境提供 |
| `live/zte-ice-pin.local.json` | 本人 ICE 网关的已核对证书固定信息 | 由已有验证环境提供 |

已有验证环境可直接在本地保留两个协议配置文件。首次准备时，复制两个模板为对应文件名，并填写从自己有权分析的客户端取得的参数。模板中的空字符串不能完成线上认证；随意生成的新密钥也不能替代服务端要求的参数。RSA PEM 使用 JSON 字符串中的 `\n` 表示换行。

两个协议配置文件已被 Git 忽略，但本地 Docker 构建会读取它们并写入镜像。因此构建好的镜像也应留在自己的部署环境中。个人账号、会话、证书固定文件和日志不会进入 Docker 构建上下文。

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

准备好上述协议配置后运行：

```sh
python -m pip install -r requirements.txt
python -X utf8 web/server.py
```

打开 **http://127.0.0.1:8765**。也可在 PowerShell 运行 `./start-web.ps1`，通过 `-Port` 改端口、`-Python` 指定解释器。

1. 保存绑定手机号；密码登录还需填写用户名和密码。账号字段留空会保留已保存的配置。
2. 选择密码或短信登录。密码登录若触发设备验证，填写该用途的最新短信验证码。多企业账号可填写企业用户名。
3. 刷新本人设备列表，选择唯一的 ZTE 云电脑并保存。
4. 准备本人网关的两个证书固定文件，点击“立即连接一次”。确认结果后，可按需要开启周期连接。

保存了会话不表示它当前仍有效；连接前会交换新 token。票据过期时需要重新登录。验证码错误或连接失败不会自动重复登录或发送短信。

## Docker 启动

使用 Docker Compose v2 和 Linux 容器。先准备根目录的两个本地协议配置，再执行：

```sh
docker compose up -d --build
```

打开 **http://127.0.0.1:8766**。默认端口避开本地 Python 服务的 8765。镜像内部监听 8765，宿主机仅发布到 127.0.0.1，网页仍检查 Host、Origin 和 CSRF。

从已有验证环境迁移账号、会话和证书：先停止周期连接并等待当前操作完成；已有容器也应先停止，然后执行：

```sh
python -X utf8 docker_import.py --source /path/to/existing/protocol
```

上一步成功后再执行 `docker compose up -d`。如果就在原协议目录中操作，可省略 `--source`。迁移会覆盖目标中的同名 JSON 文件，凭据通过标准输入传递，不放进命令行；文件由容器服务用户写入。

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
| `success` | 本次桌面连接及业务上报流程完成 |
| `desktopProtocolConnected` | 收到桌面主通道初始化 |
| `connectedReportAccepted` / `disconnectedReportAccepted` | 在线/断开业务上报被接受 |
| `expiryRenewalVerified` | 当前始终为 `false`，关机期限续延尚无证据 |

`live/*-connect-once/` 包含完整响应、连接参数、AD 凭据和二进制报文，仅留本地。网页状态接口过滤密码、验证码、token 和 AD 凭据；浏览器不使用 localStorage 保存它们。原始日志和会话均不应随代码发布。

停止周期连接会取消后续轮次，已经开始的操作继续完成清理。服务收到终止信号时最多等待85秒，Compose退出宽限为120秒；维护前可先在页面停止周期连接并等待当前操作完成。

## 验证范围

| 项目 | 已有结果 |
| --- | --- |
| 本人账号的短信/密码登录及票据交换 | 本机生产环境验证通过 |
| ZTE CAG、ICE/TLS、REDQ 主通道 | 本机连接15秒，收到初始化、版本和通道列表，响应PING并完成清理 |
| 网页触发真实单次连接 | 本机验证通过 |
| 离线检查 | 36项通过，不发送真实短信或云电脑请求 |
| Docker配置及运行时适配 | YAML、数据目录、映射端口来源校验和独立本地服务已检查 |
| 实际Docker镜像构建与容器内连接 | 交付环境未安装Docker，尚未验证 |
| 连续超过原始1–2天的关机续期效果 | 尚未验证 |

界面显示的桌面协议 `v1.2.260108` 与样本中的 `V1.2.260728` 尚未确认对应关系；连接返回的 `V7.24.30` 是 SPICE 服务端版本，不能代替界面版本。

## 离线检查

测试使用运行时生成的RSA测试密钥与模拟账号，不依赖本地真实协议参数：

```sh
python -m pip install -r test-requirements.txt
python -X utf8 -m unittest test_protocol test_desktop -v
python -X utf8 -m unittest discover -s web -p "test_*.py" -v
```

覆盖签名及RSA独立实现对照、密码/短信/挑战流程、票据刷新、上报清理、ZTE帧布局、分片读取、敏感字段过滤、并发互斥、Host/Origin/CSRF、数据迁移、首次启动及关闭处理。

## 文件结构

```text
cloudpc_protocol.py        CEM认证、签名、票据和业务接口
connect_once.py            一次真实连接与清理
zte_connection.py          新连接参数与CAG证书验证
zte_gateway_probe.py       CAG / ICE / REDQ主通道
keepalive_loop.py          独立周期连接进程
live_validate.py           本地协议审计支持
web/                       网页资源、后端与离线检查
Dockerfile / compose.yaml  容器部署定义
docker_import.py           本地账号、会话及证书迁移
*.example.json             不含密钥的协议配置模板
```
