# ePass3000 文件签名与 SSH 测试

## SSH 中文操作

主界面点击“SSH 登录 / 导出公钥”。先点击“导出 / 复制我的 SSH 公钥”，将完整公钥交给管理员加入目标账户的 `~/.ssh/authorized_keys`。Linux 上该目录通常权限为 700，文件权限为 600，所属用户应为目标用户。

填写服务器地址、端口和用户名，点击连接。首次连接与管理员提供的 SHA256 指纹核对并确认，再输入 USB Key PIN（不是服务器密码）。连接成功后可执行 `whoami`、`ls` 等非交互命令。地址、端口和用户名会记忆，PIN 不保存。

当前不是完整终端，不支持交互式 sudo、vim 等；一次命令不保留 cd 状态，可输入 `cd /path && ls`。公钥只需安装一次；拔出 Key 不会撤销已建立的 SSH 会话，请点击“断开”。主机密钥变化时会拒绝连接，应先联系管理员核实。

双击 `启动工具.cmd`。当前电脑已有 Python、cryptography 和 paramiko。
迁移机器时安装 Python 3.13，再执行 `python -m pip install -r requirements.txt`，并从原管理工具目录复制 `libusb-1.0.dll` 到此目录。USB 驱动与原工具保持一致。

先关闭 ePass3000 管理工具，保留现有槽位 1 密钥。PIN 仅在操作时输入，不保存、不自动重试。

## 文件签名

点击“文件签名”，选择文件并输入 PIN。输出原文件旁的 `.sig`（RSA2048 PKCS#1 v1.5 / SHA-256 签名）及 `.public.pem`。签名生成后先独立验签，再写入输出。
验签无需设备，选择原文件、签名、公钥。公钥必须来自可信渠道；攻击者同时替换文件、签名和公钥时，单纯验签不能确认身份。这是独立签名，不是 PDF 可视签章，也不是 CA 身份证书。

## 本地 SSH 测试和实际接入

点击“本地文件与 SSH 签名自检”：验证卡片签名、篡改拒绝和 SSH `rsa-sha2-256` 签名封装，无网络连接。

导出 SSH 公钥：

```powershell
python token_tool.py public
```

将输出的完整 `ssh-rsa ...` 公钥交给服务器管理员加入目标账户的 `authorized_keys`。公钥前缀 ssh-rsa 表示密钥类型，认证签名使用 rsa-sha2-256，不使用 SHA-1。
通过可信渠道确认服务器主机密钥，准备 OpenSSH 格式的 known_hosts 文件后：

```powershell
python token_tool.py ssh SERVER USER --port 22 --known-hosts PATH_TO_KNOWN_HOSTS
```

当前命令只验证 SSH 登录，成功后断开；不提供交互终端，也不接管 Windows 自带 ssh-agent。拒绝未知主机密钥，不自动信任。

## 验证与限制

`python -m unittest -v` 运行离线测试。`python token_tool.py selftest` 运行真实设备自检。
已用当前设备验证 RSA2048 文件签名、篡改拒绝及 SSH 格式签名的独立验签。尚未连接真实 SSH 服务器。
初始化工具预置的 PIN、PUK、维护密钥仍应在正式使用前更换；本工具不修改这些内容，也不初始化或生成密钥。

卡片 APDU / R6 协议参考 https://github.com/nickfox-taterli/ePass3000 ，实现为独立 Python 工具；SDK 解包检查后未安装旧中间件。
