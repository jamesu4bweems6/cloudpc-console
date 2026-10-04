# Docker 网页控制台

使用 Docker Compose v2 和 Linux 容器。Windows 的 Docker Desktop 选择 Linux containers。
进入克隆后的仓库根目录（包含 `compose.yaml`），并准备好 README 所述的两个本地协议配置：

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

打开 **http://127.0.0.1:8766**，也支持 http://localhost:8766。默认 8766 避开已有的本地 8765 网页服务。容器内仍监听 8765；Host/Origin 校验允许配置的宿主机端口。运行依赖独立 Python 镜像，无需 IPA、原生 SDK、Node 或数据库。

迁移工具在宿主机使用 Python 标准库，通过标准输入传送允许的 JSON 文件，并以容器服务用户写入数据卷，避免直接复制造成文件所有者不一致。不会将凭据写进命令行、镜像或终端输出。原有详细历史日志保留在宿主机，新的连接日志写入容器数据卷。另一个源目录可用 `python docker_import.py --source /path/to/protocol`；Linux/macOS 执行迁移成功后再执行 `docker compose up -d`。

## 新账号启动

```sh
docker compose up -d --build
```

首次启动生成空账号配置和固定设备身份；在网页保存手机号或用户名密码，再正常登录。真实桌面连接仍需要本人网关的 `zte-cag-pin.local.json` 和 `zte-ice-pin.local.json`，应从已有验证环境迁移至 `/data/live/`。空数据卷不会自动建立或放宽证书固定验证。当前项目已有的这两个文件可按上面的迁移流程复制。

## 数据与维护

- 账号 `/data/account.local.json`、会话和原始日志 `/data/live/` 存在 Compose 命名卷 `cloudpc-data`；代码位于只读的 `/app`。静态协议配置随镜像发布，个人账号、票据和日志被 `.dockerignore` 排除，不会进入构建上下文。
- `docker compose down` 停止并删除容器，数据卷保留；`docker compose up -d --build` 重建镜像并继续使用原数据。**`docker compose down -v` 会删除数据卷。**
- `docker compose logs -f --tail=100` 查看服务日志；`docker compose ps` 查看启动和健康检查状态。健康检查仅检查本地 HTTP 服务，不发云电脑连接请求。
- 容器启动或重启后周期连接默认关闭，需要在网页手动开启。关闭页面后服务继续运行。周期连接失败即停止；重启策略不会自动恢复周期任务。
- `docker compose stop` 发出终止信号，停止后续轮次并给当前操作最多85秒完成；Compose 给进程120秒退出时间。建议在页面停止周期连接、等待当前任务完成后再维护。
- 服务以 UID/GID 10001 运行，只有数据卷和临时目录可写。容器端口默认只发布到宿主机127.0.0.1。
- 关机期限是否被延续仍需跨原始1–2天观察验证；容器健康或连接成功均不能代替此验证。

修改端口：把 `.env.example` 复制为 `.env`，调整 `CLOUDPC_PORT=8766` 后执行 `docker compose up -d`。来源校验同步使用该端口。

如需手动 `docker run`：

```sh
docker build -t cloudpc-console:local .
docker volume create cloudpc-data
docker run -d --name cloudpc-console --init --restart unless-stopped \
  -p 127.0.0.1:8766:8765 -v cloudpc-data:/data \
  -e CLOUDPC_PUBLIC_ORIGINS=http://127.0.0.1:8766,http://localhost:8766 \
  cloudpc-console:local
```

源码也支持 `CLOUDPC_DATA_DIR` 指定数据目录；不设置时保留原本 protocol 目录的行为。原本 `start-web.ps1` 使用本机127.0.0.1监听地址；Docker 命令显式使用 `--bind 0.0.0.0`。

交付环境未安装 Docker：已完成离线回归、独立数据目录启动及映射端口来源校验，未进行实际 Linux 镜像构建、容器启动或容器内云电脑连接。部署配置参考 [Docker Compose 服务规范](https://docs.docker.com/reference/compose-file/services/)。
