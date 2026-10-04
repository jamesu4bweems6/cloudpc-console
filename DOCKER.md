# Docker 网页控制台

使用 Docker Compose v2 和 Linux 容器。Windows 的 Docker Desktop 选择 Linux containers。
进入克隆后的仓库根目录（包含 `compose.yaml`）。仓库已附带 3.6.6 样本的两组静态协议参数：

```powershell
cd cloudpc-console
```

## 迁移当前已登录账号（本机推荐）

先在原网页停止周期连接，等待当前操作完成。以下命令创建容器，迁移当前账号、会话、设备缓存和已观察的证书固定值，然后启动。首次迁移时使用；重新执行会覆盖容器中的同名配置。已有运行中的容器请先在其网页停止周期连接并等待操作完成，再运行 `docker compose stop`。

```powershell
python -X utf8 docker_import.py
if ($LASTEXITCODE -ne 0) { throw '迁移失败，未启动服务' }
docker compose up -d
docker compose ps
```

服务器本机打开 **http://127.0.0.1:8766** 或 http://localhost:8766，其他设备使用 **http://服务器IP:8766**。宿主机绑定 `0.0.0.0:8766`，容器内部监听 `0.0.0.0:8765`；IP访问必须使用配置的宿主机端口，写操作继续检查同源请求和CSRF。运行依赖独立 Python 镜像，无需 IPA、原生 SDK、Node 或数据库。控制台没有独立管理密码，应只对自己的可信设备开放8766。

迁移工具在宿主机使用 Python 标准库，通过标准输入传送允许的 JSON 文件，并以容器服务用户写入数据卷，避免直接复制造成文件所有者不一致。不会将凭据写进命令行、镜像或终端输出。原有详细历史日志保留在宿主机，新的连接日志写入容器数据卷。另一个源目录可用 `python docker_import.py --source /path/to/protocol`；Linux/macOS 执行迁移成功后再执行 `docker compose up -d`。

## 新账号启动

```sh
docker compose up -d --build
```

首次启动生成空账号配置和固定设备身份；在网页保存手机号或用户名密码，再正常登录。镜像已包含此前验证网关的两份固定值，启动时自动补齐 `/data/live/zte-cag-pin.local.json` 和 `zte-ice-pin.local.json`，已有文件不覆盖。对于同一已验证网关，换机器无需手动导入固定值。其他网关或证书变更仍需提供自己核对的固定值；程序不会关闭验证或自动接受新证书。

## 数据与维护

### 已登录但连接失败：容器缺少证书固定文件

若票据刷新成功，随后返回 `SSLError`，且 `/data/live/zte-cag-pin.local.json` 不存在，CAG HTTPS 可能因为其证书不被默认CA信任而失败。ICE也需要自己的固定文件。更新到附带默认固定值的版本并重建容器即可自动补齐，保留当前账号和登录会话：

```sh
git pull
docker compose up -d --build --force-recreate
```

网页会显示固定诊断提示及失败阶段；不会关闭证书验证来绕过错误。若已有固定文件与目标不符，需要核对后手动更新，重建不会覆盖它。

如需使用其他已核对的网关固定值，从对应验证环境取得两份文件，使用下述可选导入流程。不要重新导入整个账号目录来覆盖刚登录的会话：

```sh
git pull
docker compose stop
python -X utf8 docker_import.py --pins-only --source /path/to/verified/protocol
docker compose up -d --build
```

源目录必须同时包含 `live/zte-cag-pin.local.json` 和 `live/zte-ice-pin.local.json`。`--pins-only` 只导入这两份文件，不覆盖账号、登录票据、目标或网页设置。更新及导入后先执行一次连接确认结果，再开启周期运行。网关或证书与固定值不匹配时继续停止连接。

如果已取得仅含两份证书固定文件的本地包，可先执行 `python -m zipfile -e cmcc-gateway-pins.private.zip private-pins`，上面的 `--source` 改为 `./private-pins`。本地包和解压目录均被Git忽略。

仓库的默认文件包含网关地址与证书SHA-256，不含账号或票据。若自己的目标不同于默认网关，需要独立核对自己的网关证书。`inspect_zte_tls.py` 只观察CAG证书，不能生成ICE固定值，观察本身也不等于身份验证。

### 持久化与维护

- 账号 `/data/account.local.json`、会话和原始日志 `/data/live/` 存在 Compose 命名卷 `cloudpc-data`；代码位于只读的 `/app`。静态协议配置随镜像发布，个人账号、票据和日志被 `.dockerignore` 排除，不会进入构建上下文。
- `docker compose down` 停止并删除容器，数据卷保留；`docker compose up -d --build` 重建镜像并继续使用原数据。**`docker compose down -v` 会删除数据卷。**
- `docker compose logs -f --tail=100` 查看服务日志；`docker compose ps` 查看启动和健康检查状态。健康检查仅检查本地 HTTP 服务，不发云电脑连接请求。
- 容器启动或重启后周期连接默认关闭，需要在网页手动开启。关闭页面后服务继续运行。周期连接失败即停止；重启策略不会自动恢复周期任务。
- `docker compose stop` 发出终止信号，停止后续轮次并给当前操作最多85秒完成；Compose 给进程120秒退出时间。建议在页面停止周期连接、等待当前任务完成后再维护。
- 服务以 UID/GID 10001 运行，只有数据卷和临时目录可写。容器端口发布到宿主机所有IPv4网卡。
- 关机期限是否被延续仍需跨原始1–2天观察验证；容器健康或连接成功均不能代替此验证。

修改端口：把 `.env.example` 复制为 `.env`，调整 `CLOUDPC_PORT=8766` 后执行 `docker compose up -d`。来源校验同步使用该端口。

域名或HTTPS反向代理访问：在 `.env` 中设置 `CLOUDPC_PUBLIC_ORIGINS=https://cloudpc.example.com`，多个地址用逗号分隔，不带路径或结尾斜杠。反向代理需保留浏览器的原始Host。普通IP访问无需额外配置。

从旧版本更新监听绑定和后端校验：

```sh
git pull
docker compose up -d --build --force-recreate
docker compose ps
```

应看到 `0.0.0.0:8766->8765/tcp`。若仍无法访问，先在服务器运行 `curl http://127.0.0.1:8766/healthz` 并查看 `docker compose logs --tail=100`；本机可访问而其他设备不可访问时，再检查服务器防火墙或云安全组是否允许所需设备访问8766。重建容器保留数据卷，周期连接需在页面重新开启。

如需手动 `docker run`：

```sh
docker build -t cloudpc-console:local .
docker volume create cloudpc-data
docker run -d --name cloudpc-console --init --restart unless-stopped \
  -p 0.0.0.0:8766:8765 -v cloudpc-data:/data \
  -e CLOUDPC_PUBLIC_PORT=8766 \
  cloudpc-console:local
```

源码也支持 `CLOUDPC_DATA_DIR` 指定数据目录；不设置时保留原本 protocol 目录的行为。原本 `start-web.ps1` 使用本机127.0.0.1监听地址；Docker 命令显式使用 `--bind 0.0.0.0`。

本机交付环境未安装Docker；GitHub Actions会执行Linux镜像构建、容器HTTP启动及默认固定文件初始化检查，结果见仓库Actions。该检查不使用个人账号，容器内真实云电脑连接仍需部署后确认。部署配置参考 [Docker Compose 服务规范](https://docs.docker.com/reference/compose-file/services/)。
