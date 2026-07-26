# WinInfoSC — Windows 主机取证采集器

> 单主机、离线、事后的 Windows 主机层「一键全量取证 artifact 采集器」。
> 以管理员权限运行一个 `.bat`,把主机上散落在几十处的取证证据(事件日志、注册表持久化、
> 执行痕迹、用户活动、凭据与横向痕迹、反取证元证据……)按固定结构一次性落盘,并对全部产物
> 生成 SHA256 固证清单(chain-of-custody)。**纯系统内置命令 + 一个可选的 Everything,U 盘即用。**

---

## ⚠️ 安全声明 · 上手前请先读

本工具**完全开源**,`WinInfoSC.bat` 是一个**纯文本批处理脚本**,每一条命令都摊在明面上——**我不怕你查,就怕你不查。**

**担心投毒(供应链污染 / 后门 / 恶意载荷)?运行前请任选自证,别嫌麻烦:**

1. **丢给 AI 过审** —— 把整个 `WinInfoSC.bat` 甩给任意大模型(Claude / GPT / DeepSeek …),让它逐行解释每条命令在干什么。脚本是纯文本,AI 能给你一份逐行审计报告,哪条命令碰了什么、往哪写文件,一目了然。
2. **上平台检测** —— 把 bat 连同随包的 `Everything-x64.exe` / `Everything-x86.exe` / `es.exe` 传到 **微步云沙箱、VirusTotal** 等平台各跑一遍。(Everything/es.exe 是 [voidtools](https://www.voidtools.com) 官方便携版,可去官网自行核对文件哈希。)
3. **隔离里先跑** —— 还是不放心?先在**一次性虚拟机 / 带快照的隔离环境**里跑一遍,看它的行为、看它落了哪些产物,确认干净再上真实主机。

**用不用,主动权永远在你手里。** 取证工具本就该经得起最严苛的审视——**一个连自己都不敢让你查的工具,不配碰你的证据。**

### 📋 微步沙箱预检报告(已上传,直接点开查)

省得你自己动手——本包每个文件都已上传 **微步云沙箱(ThreatBook)** 跑过检测,报告直接看:

| 文件 | 微步沙箱检测报告 |
|------|-----------------|
| `WinInfoSC.bat` | [🔗 查看报告](https://s.threatbook.com/report/file/07e4a2249ca189e28254d3ef3d1c8e7ef90d5b580ad620215770a13c97749e75?sign=history&env=win10_1903_enx64_office2016) |
| `es.exe` | [🔗 查看报告](https://s.threatbook.com/report/file/8c587e772d195c6ed563c8122a65f132f6a92ed44936bb6ab7dc1d59fc2f20ef?sign=history&env=win10_1903_enx64_office2016) |
| `Everything-x64.exe` | [🔗 查看报告](https://s.threatbook.com/report/file/35cefe4bc4a98ad73dda4444c700aac9f749efde8f9de6a643a57a5b605bd4e7?sign=history&env=win10_1903_enx64_office2016) |
| `Everything-x86.exe` | [🔗 查看报告](https://s.threatbook.com/report/file/23b985ff329dd971e785bde1fd05f5e6e26e67ac9f2a24c7a87973a961a128fd?sign=history&env=win10_1903_enx64_office2016) |

> 上表为历史检测快照;你也可随时把文件**重新上传微步 / VirusTotal 复核**,只要文件哈希对得上,就是同一个文件。

---

## 一、这是什么

应急响应 / 事后取证时,分析人员需要的证据分布在 Windows 各个角落,手工逐个提取既慢又容易漏、
还会破坏时间线。WinInfoSC 把「该采什么、怎么绕锁采、采完怎么固证」的经验固化成一个批处理:

- **一次运行,全量落盘** —— 版本自适应(XP/2003 到 Win11 / Server),遍历所有本地用户。
- **只取证,不解读** —— 采集端只负责把原始 artifact 完整、保真地拿走;分析/研判交给专门工具或下游分析器。
- **可固证** —— 采完对每个文件算 SHA256 并汇一个「清单根哈希」,任何文件被改动 → 根哈希变。
- **零重依赖** —— 除可选的 Everything 外,全部用 Windows 自带命令(`reg` / `certutil` / `esentutl` / `robocopy` / `wmic` 等)。

> 定位:**判断留给人和下游分析器,采集端只保证「证据拿全、拿准、可追溯」。**

---

## 二、采集了什么

| 域 | 采集内容 |
|----|---------|
| **系统与进程** | `systeminfo`、环境变量、进程列表(`tasklist /V`)、服务(`tasklist /SVC`)、驱动列表、已装补丁(`qfe`)、WMIC 进程/账户/登录 |
| **网络状态** | `ipconfig /all`、DNS 缓存、`netstat`(全连接 + ESTABLISHED)、共享/会话/连接(`net share/session/use`)、`arp`、`nbtstat`、路由表、`hosts`、防火墙规则、portproxy 端口转发 |
| **持久化机制** | 注册表 Run 键(HKLM/HKCU)、Winlogon、AppInit_DLLs、BootExecute、LSA、COM 劫持、IFEO、BHO、ShellExecuteHooks、Services(三套 ControlSet)、计划任务(`Tasks\` + `schtasks`)、启动目录、**WMI 事件订阅**(无文件后门核心) |
| **执行痕迹** | Prefetch、**Amcache.hve**、BAM、ShimCache、UserAssist、MuiCache、RecentDocs、RunMRU、JumpList |
| **日志** | Windows 事件日志(NT6 `.evtx` / NT5 `.evt`)、防火墙日志、Netlogon 日志、360/天擎日志、IIS 日志、ScreenOn |
| **用户活动** | Recent、**Windows Timeline**(ActivitiesCache)、**PowerShell 历史**、浏览器(Chrome/Edge 的 History/Cookies/Login Data/Downloads、Firefox)、**ShellBags**(UsrClass.dat) |
| **凭据与横向** | RDP(服务器历史 / 位图缓存 / `Default.rdp`)、**SSH 密钥**(用户 + 全局)、凭据保险箱(`vaultcmd`)、**Wi-Fi 明文密码**(`netsh wlan export key=clear`)、`cmdkey` |
| **USB 与设备史** | USBSTOR、USB、MountPoints2 |
| **反取证元证据** | **审计策略**(`auditpol`,判日志是否被提前关)、Windows Defender 排除项 / 检测历史 / 策略、**VSS 卷影副本**、BITS 后台作业、回收站元数据 |
| **资源数据库** | **SRUM**(`SRUDB.dat`,近 30 天每程序网络收发字节)+ **Windows 搜索索引**(`Windows.edb`,搜索历史/文件与邮件索引元数据) |
| **注册表 hive**(二进制) | 四大 hive:`SAM`(账户/密码哈希)、`SECURITY`(LSA secrets/缓存凭据)、`SYSTEM`(服务/USB/网络)、`SOFTWARE`(SRUM 反解 AppID/网卡) |
| **Win11 Recall**(回顾) | `CoreAIPlatform` 回顾取证:**屏幕截图历史**(`ImageStore`)+ **活动数据库**(`ukg.db`,含 OCR 文本)+ 语义向量库(`*.sidb`)+ 开关注册表(Win11 24H2+) |
| **文件系统时间线** | **`$UsnJrnl`**(USN 变更日志,文件增删改流水·含已删文件痕迹,`fsutil`)+ **`$MFT`**(主文件表,全盘文件元数据+时间戳·含已删,**可选**需 RawCopy) |
| **远程控制痕迹** | **AnyDesk / TeamViewer / ToDesk / 向日葵**(SunLogin) 的连接记录与日志(横向移动·外联入口) |
| **易失状态快照** | 采集流程**最先**抓(order of volatility):进程(`tasklist`)、网络连接(`netstat`)、会话(`net session/use`)、ARP/DNS 缓存 + **采集时刻·时区锚点**(`_COLLECTION_TIME.txt`) |
| **全盘清单** | `everything.efu`(可选,需随包带 Everything) |
| **固证与日志** | `_HASH_MANIFEST.txt`(逐文件 SHA256 + 根哈希)、`_COLLECT_ERRORS.log`(主干命令失败记录) |

**多用户遍历**:自动遍历 `C:\Users\*`,对每个用户单独采集浏览器 / PSHistory / ShellBags / Timeline / SSH,
并加载其 `NTUSER.DAT` 导出用户级注册表项(UserAssist / RunMRU / RecentDocs / COM 劫持 等)。

---

## 三、使用方法

### 前置
- **必须以管理员权限运行**(脚本自检,非管理员直接退出)。
- **从工具包目录内运行**:别把 `.bat` 单独拷出去,连同 Everything 一起放在同一目录运行。

### 运行
1. 把整个 `WinInfoSC/` 目录拷到靶机(U 盘 / 网络盘均可)。
2. 右键 `WinInfoSC.bat` → **以管理员身份运行**(或在管理员 cmd 里执行)。
3. 脚本自动取本机 IP + 主机名,在 **bat 所在目录**生成 `Forensic_<IP>_<主机名>\`,采集完成打印清单根哈希。

### 产出
- **`Forensic_<IP>_<主机名>\`** —— 采集目录,结构即下游分析器的输入契约。
- **`_HASH_MANIFEST.txt`** —— 全部产物逐文件 SHA256 + 一个**清单根哈希**(完整性凭证)。
- **`_COLLECT_ERRORS.log`** —— 记录「本该成功却失败」的主干命令;为空(仅表头)即全部成功。

### 取走
采集结束,把整个 `Forensic_<IP>_<主机名>\` 目录拷到分析机即可。

---

## 四、随包工具

发布包内已含 **Everything 便携版**(voidtools 官方):

> 🔴 **关于 `Everything.exe` / `es.exe`(第三方免费工具,非本项目自研)**
>
> - **是什么**:<span style="color:red">**`Everything` 是 voidtools 出品的免费文件搜索工具**</span>,读 NTFS 主文件表秒建全盘索引;<span style="color:red">**`es.exe` 是它的命令行客户端**</span>。本脚本只用它导出一份全盘文件清单(`everything.efu`),别无它用。
> - **来源**:<span style="color:red">**官方唯一来源 → https://www.voidtools.com**</span>。不信任随包的这两个 exe,**完全可以自己去官网下载便携版替换**,并自行核对文件哈希(呼应本文开头的安全声明)。
> - <span style="color:red">**不带这俩也能跑!**</span> 把 `Everything-x64.exe`/`Everything-x86.exe`/`es.exe` 删掉,脚本会**自动跳过**全盘清单那一步、**不报错、不影响主采集**——它俩只是可选增强,不是取证核心。

| 文件 | 作用 |
|------|------|
| `Everything-x64.exe` / `Everything-x86.exe` | 全盘文件清单引擎;bat 按 CPU 架构**自动选**(64 位/WOW64/ARM64 用 x64,否则 x86) |
| `es.exe` | Everything 命令行客户端,导出 `everything.efu` 全盘清单 |

- Everything 用**独立命名实例**(`Forensic`)+ 不落库(`-nodb`)后台建索引,导出后即退出,**尽量减少留痕**。
- **缺 Everything 不影响主采集**:脚本自动跳过该步、**不记为失败**。
- **`$MFT` 采集需自备 RawCopy(不随包)**:若要采集 `$MFT` 主文件表(全盘文件元数据·含已删),自行去 🔗 [**jschicht/RawCopy**](https://github.com/jschicht/RawCopy) 下载 `RawCopy64.exe` / `RawCopy.exe` 放进本目录即可;**不放则自动跳过**(可选增强,不影响其余采集)。

> **关于 SRUM:采集端不需要任何额外工具。** `SRUDB.dat` 与 `SOFTWARE` hive 用 Windows **自带的
> `esentutl` / `reg save`** 绕锁取出。SRUM 的**解析**(转 xlsx/csv)属于下游查看工具,见第五节。

---

## 五、产物如何查看

采集端拿到的多是**二进制原始文件**,不能直接读,需对应工具解析。常用对照:

| 产物 | 类型 | 推荐查看 / 解析工具 |
|------|------|--------------------|
| `SRUDB.dat` + `SOFTWARE` | ESE 数据库 | **srum-dump**(MarkBaggett,→ **xlsx**) · SrumECmd(Eric Zimmerman,→ csv) |
| `Windows.edb` | ESE 搜索索引 | WinSearchDBAnalyzer · esedbexport(libesedb) |
| `Recall_CurrentUser`(`ukg.db`+`ImageStore`) | SQLite + JPEG | DB Browser for SQLite 看 `ukg.db`(App/WindowCapture/OCR 文本表) · 图片查看器看截图 |
| `usn_journal_C.csv` | USN 变更日志 | 文本/Excel 直接看 · UsnJrnl2Csv |
| `MFT.bin` | $MFT 二进制 | **MFTECmd**(Eric Zimmerman → csv,含已删文件完整时间线) |
| `RemoteAccess/*` | 远控日志 | 文本编辑器(AnyDesk `connection_trace.txt` / TeamViewer `Connections_incoming.txt`) |
| `Windows_logs\*.evtx` | 事件日志 | Windows 事件查看器 · EvtxECmd |
| `SAM`·`SECURITY`·`SYSTEM`·`Amcache.hve`·`SOFTWARE`·`NTUSER.DAT`·`UsrClass.dat` | 注册表 hive | Registry Explorer · RegRipper(`SAM`/`SECURITY` 可提账户/凭据,需配 `SYSTEM` 的 bootkey) |
| `Prefetch\*.pf` | Prefetch | PECmd · WinPrefetchView |
| `ShellBags\UsrClass.dat` | ShellBags | ShellBags Explorer |
| 浏览器 `History`/`Cookies`/`Login Data` | SQLite | DB Browser for SQLite |
| `JumpList` | 跳转列表 | JLECmd |
| `everything.efu` | 全盘清单 | Everything(File → Open File List) |
| `REG_*.txt`·`*.txt`·`*.csv` | 文本 | 任意文本编辑器 |
| `_HASH_MANIFEST.txt` | 固证清单 | `certutil -hashfile` / `sha256sum` 复算校验 |

> **SRUM → xlsx 快速上手**:用 srum-dump,喂 `SRUDB.dat` 和同采的 `SOFTWARE` hive(用于把 AppID / 网卡 LUID
> 反解成可读的程序名和网卡名),即可导出各表 xlsx。SRUM 表含**近 30 天每程序的网络收发字节**——
> 判断「哪个程序跑过、外传了多少」的关键证据。

---

## 六、设计亮点

1. **Chain-of-custody 固证** —— 采完用内置 `certutil` 逐文件 SHA256,再汇一个清单根哈希做单一完整性锚点;任何篡改 → 根哈希变。
2. **失败可见,不噪声** —— `_COLLECT_ERRORS.log` 只记「本该成功却失败」的确定性命令(缺工具/权限不足/系统错误);目录拷贝类源不存在属常态,不记。
3. **零重依赖,U 盘即用** —— 除可选 Everything 外全用系统内置命令,无需安装、无需运行时。
4. **绕锁采集** —— 被占用的 hive / 浏览器库 / SRUDB / UsrClass 用 `robocopy /B` 备份模式、`esentutl /y`、`reg load` 绕过占用。
5. **版本自适应** —— 按 `ver` 自动分 NT5(XP/2003,经典 `.evt`)/ NT6(Win7–11 + Server,`.evtx` + Amcache/BAM/Timeline);Win7 单独处理代码页。
6. **多用户全覆盖** —— 遍历所有本地用户,而非只当前用户。
7. **减留痕** —— Everything 独立实例 + 不落库 + 采完即退;采集自身产生的痕迹下游分析器可据指纹排除。
8. **面向分析契约** —— 产物目录结构即下游分析器的输入契约;`SRUDB.dat` 与 `SOFTWARE` 同采,保证 SRUM 能反解可读名。

---

## 七、注意事项与边界

- ⚠️ **采集动作本身会在主机留痕**(产生新的 Prefetch / Amcache 等)——这是取证的固有代价。
- ⚠️ **首次使用务必先在一次性 Windows VM 上以管理员权限冒烟跑一遍**,确认目录结构与 manifest 正常生成,再上真实靶机。
- ⚠️ 含 `!` 的文件名在延迟扩展下路径可能变形(取证产物罕见);大集合逐文件 SHA256 较慢(可接受)。
- 采集包请**保持目录完整、从包内运行**;工具包路径尽量避免含空格(脚本已对自身路径加引号加固)。

---

## 八、更新记录

### 2026-07-26 · 配套分析端:规范时区名、采集足迹自报告、wmic 弃用兜底

**背景**:下游分析端在三处需要采集端配套——

1. **`tzutil /g` 规范时区名** —— `_COLLECTION_TIME.txt` 里 `w32tm /tz` 在无夏令时规则的时区(如中国)会报 `TIME_ZONE_ID_UNKNOWN`,分析端拿不到规范时区名。现在追加一行 `tzutil /g: China Standard Time`。
2. **`_COLLECT_FOOTPRINT.txt` 采集足迹自报告(新增,与 `_HASH_MANIFEST.txt` 同级)** —— 采集过程执行的关键外部命令(tasklist/netstat/ipconfig/arp/route/nbtstat/net/netsh/reg/schtasks/wmic/driverquery/auditpol/cmdkey/bitsadmin/systeminfo/w32tm/tzutil/es/Everything 等)逐条记录为 `YYYY-MM-DD HH:MM:SS<TAB>命令行`,供分析端 collector footprint 标注优先消费。certutil 批量固证属固证动作,只记一条汇总(含文件数),不逐条刷屏。时间戳优先用 PowerShell `Get-Date` 取标准格式,无 PowerShell 时退化为 `%DATE% %TIME%`。
3. **wmic 弃用兜底** —— 新版 Windows 已移除 wmic,`wmic process/useraccount/logon/qfe` 失败(exit≠0)时自动兜底:进程 → `tasklist /V /FO LIST`(产出 `tasklist_process.txt`);账户 → 前面 `net user` 已采集,跳过仅记录;登录会话 → `query user`(`query_user_logon.txt`);补丁 → 从已采的 `systeminfo.txt` 提取 KB 行(`qfe_from_systeminfo.txt`)。兜底情况写入 `_COLLECT_ERRORS.log` 并注明「wmic 不可用,已用 XX 兜底」。

### 2026-07-23 · 修复 Everything 全盘清单导出失败(`Error 8: IPC window not found`)

**现象**:采集跑到 Everything 那步报 `Error 8: Everything IPC window not found`,`everything.efu` 导不出来(部分环境还表现为"Everything 没弹出来")。

**根因**:早期为"减少留痕"给 Everything 加的几个参数,反而把功能搞坏了:

| 参数 | 问题 |
|------|------|
| `-nodb` | 不建索引数据库 → Everything 没有可响应的 IPC 窗口 → es.exe 连不上 |
| `-noapp-data` | 与 `start` 命令冲突 → 命名实例根本不启动、Everything 不弹窗 |
| `-startup` | 一并去除 |

**修复**:去掉这三个冲突参数,只保留 `-instance Forensic` 命名实例——**隔离靠命名实例本身**(它和系统已装的默认 Everything 互不干扰);启动后加 ~11 秒等待让实例建索引就绪;采集完 `del %APPDATA%\Everything\*Forensic*` 清理实例配置。"减留痕"的目标改用**实例隔离 + 采完清理**达成,不再靠会打架的参数。

> **IPC 澄清**:报错里的 "IPC window" 是 Everything 的**本机进程间通信窗口**(es.exe ↔ Everything.exe 本地对话),**不监听任何网络端口、不开 web/FTP、不对外**,不违背取证隔离原则。采集时可自行 `netstat -ano | findstr LISTENING` 对 Everything 的 PID 核验。

---

## 九、许可

见仓库根 `LICENSE`。Everything 为 voidtools 第三方软件,遵循其各自许可,不随本项目分发源码。
