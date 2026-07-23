@echo off
color 0b
@echo ***************************************************************
echo.
echo                       W I N I N F O S C
echo              Windows Host Forensic Collector
echo                           by ymher
echo.
echo ***************************************************************
echo.
echo.

:: 要求以管理员权限运行
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if '%errorlevel%' NEQ '0' (
 color 0c
 echo [!] Please run with administrator rights
 echo.
 pause
 exit
)

:: 开启延迟变量扩展，供后续for循环中errorlevel判断使用
setlocal enabledelayedexpansion

echo.
echo [*] Start gathering info,please wait......
echo.
:: ============================================================
:: Everything 全盘文件清单导出（可选增强）
:: 采集包需与 bat 同目录随包带: Everything-x64.exe + Everything-x86.exe + es.exe (voidtools 官方便携版)
:: 流程: 按 CPU 架构选 exe → 独立命名实例(Forensic·实例级隔离)后台建索引 →
::       es.exe -timeout 等索引就绪后导出全盘 efu → 退出该实例(减少留痕)。
:: 缺工具→跳过(不算失败); 带齐却导出失败→记 FAIL。
:: ============================================================
:: 按 CPU 架构选择 Everything 便携版(默认 x86 兜底老系统; 64 位系统用 x64)
set "EVERYTHING_EXE=Everything-x86.exe"
if /I "%PROCESSOR_ARCHITECTURE%"=="AMD64" set "EVERYTHING_EXE=Everything-x64.exe"
if /I "%PROCESSOR_ARCHITECTURE%"=="ARM64" set "EVERYTHING_EXE=Everything-x64.exe"
if defined PROCESSOR_ARCHITEW6432 set "EVERYTHING_EXE=Everything-x64.exe"
if exist "%~dp0es.exe" (
    if exist "%~dp0%EVERYTHING_EXE%" (
        echo [*] Everything: building portable index [instance=Forensic], please wait...
        start "" "%~dp0%EVERYTHING_EXE%" -instance Forensic
        :: 等命名实例启动+建索引就绪(否则 es.exe 报 Error 8: IPC window not found)
        ping -n 12 127.0.0.1 >nul 2>&1
        "%~dp0es.exe" -instance Forensic -timeout 120000 -export-efu "%~dp0everything.efu" || set "ES_FAILED=1"
        "%~dp0%EVERYTHING_EXE%" -instance Forensic -exit >nul 2>&1
        :: 采完删掉 Everything 生成的库/配置(补回"减留痕")
        del /q "%APPDATA%\Everything\*Forensic*" >nul 2>&1
    ) else (
        echo [!] 缺 %EVERYTHING_EXE%, 跳过 efu 全盘清单导出 ^(需与 es.exe 同目录^)
    )
)
md "%~dp0Forensic"
pushd "%~dp0Forensic"

:: 处理文件夹名称
:: GetIP
for /f "tokens=4" %%a in ('route print^|findstr 0.0.0.0.*0.0.0.0') do (
 set IP=%%a
goto :cha
)
:cha
if "%IP%"=="" (set IP=noip)
:: GetNAME
for /f "" %%i in ('hostname') do (
set NAME=%%i
goto :chd
)
:chd
:: 输出文件夹名
set NEWNAME=Forensic_%IP%_%NAME%
cd ..
ren Forensic "%NEWNAME%"

::剪切efu文件（仅当成功导出时，避免文件不存在时报错刷屏）
if exist "%~dp0everything.efu" move "%~dp0everything.efu" "%NEWNAME%"

cd "%NEWNAME%"

:: ============================================================
:: 失败命令日志：记录主干命令异常退出（缺工具 / not recognized / 权限不足 / 系统错误）
:: 仅记"本该成功却失败"的确定性命令；目录拷贝类(xcopy/robocopy)源不存在属常态，不在此列。
:: ============================================================
set "FAILLOG=%CD%\_COLLECT_ERRORS.log"
> "%FAILLOG%" echo WinInfoSC Forensic Collection - Failed Commands Log
>> "%FAILLOG%" echo Host=%NAME% IP=%IP% Generated=%DATE% %TIME%
>> "%FAILLOG%" echo ============================================================
if defined ES_FAILED >> "%FAILLOG%" echo [%TIME%] FAIL es.exe (everything.efu export)

:: ============================================================
:: 【易失优先 order-of-volatility】采集时刻 + 实时状态快照
:: 进程/网络连接/会话/缓存/USN 随时间或关机即变,必须在磁盘 artifact 前最先采
:: ============================================================
> _COLLECTION_TIME.txt echo WinInfoSC Collection Started: %DATE% %TIME%
w32tm /tz >> _COLLECTION_TIME.txt 2>nul
tasklist /V /FO CSV > tasklist_process.csv || call :fail "tasklist /V"
tasklist /SVC /FO CSV > tasklist_services.csv || call :fail "tasklist /SVC"
netstat -abon >> netstat.txt || call :fail "netstat -abon"
netstat -aon | FIND "ESTABLISHED" > netstat_established.txt
ipconfig /displaydns > dns_cache.txt || call :fail "ipconfig /displaydns"
arp -a > arp_a.txt || call :fail "arp -a"
nbtstat -S > nbtstat_cache.txt || call :fail "nbtstat -S"
net session > net_session.txt || call :fail "net session"
net use > net_use.txt || call :fail "net use"
:: USN 变更日志(文件系统增删改流水,含已删文件痕迹) —— 亦属易失
fsutil usn readjournal C: csv > usn_journal_C.csv 2>nul
:: ============================================================
:: $MFT 主文件表(全盘文件元数据+时间戳,含已删文件) —— 需 RawCopy(裸磁盘读)
:: 可选: 采集包内放 RawCopy64.exe/RawCopy.exe 才采,缺则跳过(不算失败)
:: ============================================================
set "RAWCOPY_EXE="
if exist "%~dp0RawCopy64.exe" set "RAWCOPY_EXE=RawCopy64.exe"
if not defined RAWCOPY_EXE if exist "%~dp0RawCopy.exe" set "RAWCOPY_EXE=RawCopy.exe"
if defined RAWCOPY_EXE (
    echo [*] Acquiring $MFT via %RAWCOPY_EXE% ^(may take a while^)...
    "%~dp0%RAWCOPY_EXE%" /FileNamePath:C:0 /OutputPath:. /OutputName:MFT.bin >nul 2>&1
) else (
    echo [!] Skip $MFT ^(no RawCopy.exe, optional^)
)

:: 先收集环境变量、收集pf文件
set > Enviromment_var.txt
:: 判断存在PF文件再复制
dir %SYSTEMROOT%\Prefetch\*.pf >nul 2>&1
if '%errorlevel%' == '0' (
md Prefetch
dir /tc /q %SYSTEMROOT%\Prefetch\*.pf > .\Prefetch\_pflist.txt
xcopy /e/h/c/i  %SYSTEMROOT%\Prefetch\*.pf  .\Prefetch
)

:: 获取蓝屏文件--如不必须可利用::注释
:: md BSOD_DUMP
:: copy /Y %SYSTEMROOT%\MEMORY.DMP  .\BSOD_DUMP\
:: copy /Y %SYSTEMROOT%\Minidump  .\BSOD_DUMP\

:: ============================================================
:: 注册表采集 - 原有项
:: ============================================================
reg export  "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" REG_Shimcache.txt || call :fail "reg Shimcache"
reg export  "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist" REG_UserAssit.txt || call :fail "reg UserAssist"
reg export  "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"  REG_IFEO.txt || call :fail "reg IFEO"
reg export  "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"  REG_CurrentVersionRun.txt || call :fail "reg HKLM Run"
reg export  "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"  REG_BHO.txt || call :fail "reg BHO"
reg export  "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks"   REG_ShellExecuteHooks.txt || call :fail "reg ShellExecuteHooks"
reg export  "HKLM\SYSTEM\CurrentControlSet\Services"  REG_CurrentControlSet_Services.txt || call :fail "reg Services"
reg export  "HKLM\SYSTEM\ControlSet001\Services"  REG_ControlSet001_Services.txt || call :fail "reg ControlSet001 Services"
reg export  "HKLM\SYSTEM\ControlSet002\Services"  REG_ControlSet002_Services.txt || call :fail "reg ControlSet002 Services"
reg export  "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" REG_RunMRU.txt || call :fail "reg RunMRU"
reg export  "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" REG_RecentDocs.txt || call :fail "reg RecentDocs"

:: ============================================================
:: 注册表采集 - 新增：持久化机制
:: ============================================================
:: Winlogon - Shell/Userinit劫持
reg export  "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"  REG_Winlogon.txt 2>nul
:: AppInit_DLLs - 加载每个user-mode进程的DLL
reg export  "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"  REG_AppInitDLLs.txt 2>nul
:: BootExecute - 开机最早执行阶段
reg export  "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager"  REG_SessionManager.txt 2>nul
:: LSA - SSP注入、WDigest明文凭据开关
reg export  "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"  REG_LSA.txt 2>nul
:: COM劫持 - HKCU优先于HKLM加载，无需管理员权限
reg export  "HKCU\Software\Classes\CLSID"  REG_COM_Hijack_HKCU.txt 2>nul
:: 用户级Run键
reg export  "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"  REG_HKCU_Run.txt 2>nul

:: ============================================================
:: 注册表采集 - 新增：USB设备接入历史
:: ============================================================
reg export  "HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR"  REG_USBSTOR.txt 2>nul
reg export  "HKLM\SYSTEM\CurrentControlSet\Enum\USB"  REG_USB.txt 2>nul
reg export  "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2"  REG_MountPoints2.txt 2>nul

:: ============================================================
:: 注册表采集 - 新增：RDP客户端历史
:: ============================================================
reg export  "HKCU\Software\Microsoft\Terminal Server Client\Servers"  REG_RDPServers.txt 2>nul
reg export  "HKCU\Software\Microsoft\Terminal Server Client\Default"   REG_RDPDefault.txt 2>nul

:: ============================================================
:: 注册表采集 - 新增：网络历史
:: ============================================================
reg export  "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles"    REG_NetworkProfiles.txt 2>nul
reg export  "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures"  REG_NetworkSignatures.txt 2>nul

:: ============================================================
:: 注册表采集 - 新增：Windows Defender排除项（攻击者常写入白名单）
:: ============================================================
reg export  "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions"  REG_DefenderExclusions.txt 2>nul
reg export  "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender"     REG_DefenderPolicy.txt 2>nul

md Windows_logs
::判断系统版本,根据系统版本获取日志及最近访问文件
for /f "tokens=1* delims=[" %%a in ('ver') do set b=%%b
set b=%b:* =%
set b=%b:~0,1%
if "%b%" == "5" (
 goto :NT5
) else (goto :NT6)

:NT5
::for XP 2000 2003
copy /y %SYSTEMROOT%\System32\config\*.evt  .\Windows_logs\
md Recent
xcopy /e/h/c/i "%USERPROFILE%\Recent" .\Recent
reg export  "HKCU\Software\Microsoft\Windows\ShellNoRoam\MUICache" REG_MuiCache.txt
goto :MoreInfo

:NT6
::for vista 7 8 8.1 10
xcopy /e/h/c/i %SYSTEMROOT%\System32\winevt\Logs  .\Windows_logs\
::快捷键
xcopy /e/h/c/i "%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations" .\JumpList\
::天擎日志(如有)
xcopy /e/h/c/i "%ProgramFiles(x86)%\360\360Safe\deepscan\Log" .\360log\
xcopy /e/h/c/i "%ProgramFiles(x86)%\QAX\360safe\deepscan\Log" .\QAXlog\
::计划任务
xcopy /e/h/c C:\Windows\System32\Tasks .\Tasks\System32
xcopy /e/h/c C:\Windows\SysWOW64\Tasks .\Tasks\SysWOW64
::certutil下发缓存
xcopy /e/h/c/i C:\Users\Administrator\AppData\LocalLow\Microsoft\CryptnetUrlCache .\Virus\certutil\Administrator
xcopy /e/h/c/i C:\Windows\SysWOW64\config\systemprofile\AppData\LocalLow\Microsoft\CryptnetUrlCache\ .\Virus\certutil\SysWOW64
xcopy /e/h/c/i "%USERPROFILE%\AppData\LocalLow\Microsoft\CryptnetUrlCache" .\Virus\certutil\User
::ScreenOn日志
xcopy /e/h/c/i C:\Windows\System32\SleepStudy\ScreenOn\ .\ScreenOn
::Temp
xcopy /e/h/c/i %SYSTEMROOT%\TEMP .\Temp
md Recent
xcopy /e/h/c/i "%APPDATA%\Microsoft\Windows\Recent"  .\Recent\
reg export  "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache" REG_MuiCache.txt
::win10 only
reg export  "HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings" REG_UserSettings.txt
::Amcache.hve 常被系统占用 → robocopy 备份模式绕锁（与其它 hive 取法一致）
robocopy "%SYSTEMROOT%\AppCompat\Programs" . Amcache.hve /B /COPY:DAT /R:0 /W:0 >nul 2>&1

:: ============================================================
:: NT6新增 - RDP客户端遗留文件（当前用户）
:: ============================================================
xcopy /e/h/c/i "%LOCALAPPDATA%\Microsoft\Terminal Server Client\Cache" .\RDPBitmapCache\ >nul 2>&1
if exist "%USERPROFILE%\Documents\Default.rdp" copy /y "%USERPROFILE%\Documents\Default.rdp" .\RDPBitmapCache\ >nul 2>&1

:: ============================================================
:: NT6新增 - Windows Timeline ActivitiesCache（当前用户）
:: ============================================================
xcopy /e/h/c/i "%LOCALAPPDATA%\ConnectedDevicesPlatform" .\ActivitiesCache\ >nul 2>&1

:: ============================================================
:: NT6新增 - PowerShell命令历史（当前用户）
:: ============================================================
xcopy /h/c/i "%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" .\PSHistory\ >nul 2>&1

:: ============================================================
:: NT6新增 - 启动目录（当前用户 + 全局）
:: ============================================================
xcopy /e/h/c/i "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup" .\Startup\CurrentUser\ >nul 2>&1
xcopy /e/h/c/i "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" .\Startup\Global\ >nul 2>&1

:: ============================================================
:: NT6新增 - UsrClass.dat Shellbags（当前用户，robocopy备份模式绕过锁定）
:: ============================================================
robocopy "%LOCALAPPDATA%\Microsoft\Windows" .\ShellBags_CurrentUser UsrClass.dat /B /COPY:DAT /R:0 /W:0 >nul 2>&1

:: ============================================================
:: NT6新增 - Defender检测历史
:: ============================================================
xcopy /e/h/c/i "C:\ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory" .\DefenderHistory\ >nul 2>&1

:: ============================================================
:: NT6新增 - SSH密钥（当前用户 + 全局）
:: ============================================================
xcopy /e/h/c/i "%USERPROFILE%\.ssh" .\SSH\CurrentUser\ >nul 2>&1
xcopy /e/h/c/i "C:\ProgramData\ssh" .\SSH\Global\ >nul 2>&1

:: ============================================================
:: NT6新增 - Windows 11 Recall(回顾)取证 [Win11 24H2+, 当前用户]
:: 屏幕截图历史(ImageStore JPEG)+活动数据库(ukg.db SQLite)+语义向量库(*.sidb)
:: %LOCALAPPDATA%\CoreAIPlatform.00\UKP\<GUID>\ ; robocopy /B 绕 SQLite 锁
:: ============================================================
robocopy "%LOCALAPPDATA%\CoreAIPlatform.00\UKP" .\Recall_CurrentUser /E /B /COPY:DAT /R:0 /W:0 >nul 2>&1
:: Recall 开关/策略注册表(WindowsAI)
reg export "HKCU\Software\Policies\Microsoft\Windows\WindowsAI" REG_Recall_WindowsAI_HKCU.txt 2>nul
reg export "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" REG_Recall_WindowsAI_HKLM.txt 2>nul

:: ============================================================
:: NT6新增 - 远程控制软件痕迹(横向/外联入口: AnyDesk/TeamViewer/ToDesk/向日葵)
:: ============================================================
xcopy /e/h/c/i "%APPDATA%\AnyDesk" .\RemoteAccess\AnyDesk\ >nul 2>&1
xcopy /e/h/c/i "%APPDATA%\TeamViewer" .\RemoteAccess\TeamViewer\ >nul 2>&1
xcopy /e/h/c/i "%ProgramData%\TeamViewer" .\RemoteAccess\TeamViewer_ProgramData\ >nul 2>&1
xcopy /e/h/c/i "%APPDATA%\ToDesk" .\RemoteAccess\ToDesk\ >nul 2>&1
xcopy /e/h/c/i "%ProgramData%\ToDesk" .\RemoteAccess\ToDesk_ProgramData\ >nul 2>&1
xcopy /e/h/c/i "%ProgramData%\Oray" .\RemoteAccess\Sunlogin_Oray\ >nul 2>&1

goto :MoreInfo

:MoreInfo
echo.
echo [*] Gathering info...please wait several seconds :)
echo.

copy /y %SYSTEMROOT%\System32\drivers\etc\hosts .\hosts.txt || call :fail "copy hosts"
ipconfig /all  > ipconfig.txt || call :fail "ipconfig /all"
systeminfo > systeminfo.txt || call :fail "systeminfo"
net share > net_share.txt || call :fail "net share"
net user > net_user.txt || call :fail "net user"
net user Administrator >net_user_Administrator.txt || call :fail "net user Administrator"
::如非域环境net view过于影响脚本性能，默认注释。
::net view > net_view.txt
cmdkey /l >cmdkey.txt || call :fail "cmdkey /l"
netsh advfirewall firewall show rule name=all >netsh_firewall_all.txt || call :fail "netsh firewall rules"
netsh interface portproxy show all >netsh_portproxy_all.txt || call :fail "netsh portproxy"
route print >route_print.txt || call :fail "route print"
net localgroup > net_localgroup.txt || call :fail "net localgroup"
net localgroup administrators > net_localgroup_admin.txt || call :fail "net localgroup administrators"
regedit /e .\regedit.reg || call :fail "regedit /e"
dir /TC /AH %SYSTEMROOT%\System32 > dir_system32_hide.txt
dir /tc /q /a %SYSTEMROOT%\Fonts | findstr /v /i "\.fon \.ttf \.ttc \.otf \. \.. \.CompositeFont desktop\.ini fms_metadata\.xml StaticCache\.dat" > dir_fonts.txt

:: ============================================================
:: 新增 - 网络补充
:: ============================================================
::Wi-Fi历史及明文密码（netsh wlan export需要有无线网卡）
netsh wlan show profiles > wifi_profiles.txt 2>nul
netsh wlan export profile folder=.\WiFiProfiles key=clear >nul 2>&1

::防火墙日志文件（如已启用）
copy /y "%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log" .\pfirewall.log >nul 2>&1

::域环境Netlogon日志
copy /y "%SystemRoot%\debug\netlogon.log" .\netlogon.log >nul 2>&1
copy /y "%SystemRoot%\debug\netlogon.bak" .\netlogon.bak >nul 2>&1

:: ============================================================
:: 新增 - 系统安全状态
:: ============================================================
::审计策略（判断日志是否被提前关闭，取证结论的元证据）
auditpol /get /category:* > auditpol.txt 2>nul

::凭据保险箱
vaultcmd /listcreds:"Windows Credentials" /all > vault_creds.txt 2>nul
vaultcmd /listcreds:"Web Credentials" /all >> vault_creds.txt 2>nul

::驱动列表
driverquery /FO CSV /V > driverquery.csv || call :fail "driverquery"

::VSS卷影副本枚举（判断攻击者是否已删除）
vssadmin list shadows > vss_shadows.txt 2>nul
vssadmin list shadowstorage >> vss_shadows.txt 2>nul

::BITS后台传输作业（隐蔽下载/持久化）
bitsadmin /list /allusers /verbose > bits_jobs.txt 2>nul

::回收站元数据（$I文件含原始路径和删除时间）
dir /a /s C:\$Recycle.Bin > recycle_bin_list.txt 2>nul

::IIS日志（如有IIS）
xcopy /e/h/c/i "%SystemRoot%\System32\LogFiles\W3SVC1" .\IIS_Logs\ >nul 2>&1

:: ============================================================
:: 新增 - WMI持久化订阅（无文件后门核心手段，原生wmic可查）
:: ============================================================
md WMI_Subscription
wmic /namespace:\\root\subscription PATH __EventFilter GET * /format:list > .\WMI_Subscription\EventFilter.txt 2>nul
wmic /namespace:\\root\subscription PATH __EventConsumer GET * /format:list > .\WMI_Subscription\EventConsumer.txt 2>nul
wmic /namespace:\\root\subscription PATH __FilterToConsumerBinding GET * /format:list > .\WMI_Subscription\FilterToConsumerBinding.txt 2>nul

:: ============================================================
:: 新增 - SRUM数据库原始文件（esentutl可绕过ESE锁定）
:: ============================================================
esentutl /y "%SystemRoot%\System32\sru\SRUDB.dat" /d .\SRUDB.dat /o >nul 2>&1
:: Windows 搜索索引数据库(ESE) - 搜索历史/文件与邮件索引元数据(esentutl 绕 ESE 锁)
esentutl /y "%ProgramData%\Microsoft\Search\Data\Applications\Windows\Windows.edb" /d .\Windows.edb /o >nul 2>&1
:: SOFTWARE hive二进制 - srum-dump -r 用于把AppID/网卡LUID反解为可读名
:: 采集时只有一次机会，须与SRUDB.dat同采，否则SRUM解析降级为裸数字
reg save HKLM\SOFTWARE .\SOFTWARE /y >nul 2>&1
:: 传统四大 hive 二进制补齐(SAM=账户/哈希, SECURITY=LSA secrets, SYSTEM=服务/USB/网络)
reg save HKLM\SAM .\SAM /y >nul 2>&1
reg save HKLM\SECURITY .\SECURITY /y >nul 2>&1
reg save HKLM\SYSTEM .\SYSTEM /y >nul 2>&1

:: 判断Win7/2008系统
for /f "tokens=1* delims=[" %%a in ('ver') do set b=%%b
set b=%b:* =%
set b=%b:~0,3%
if "%b%" == "6.1" (
	goto :win7only
) else (
	schtasks /query /FO LIST /V > schtasks.txt || call :fail "schtasks /query"
	goto :continue
)


:: 更改字符集
:win7only
for /f "tokens=2 delims=:" %%i in ('chcp') do set codepage=%%i
if "%codepage%" NEQ " 437" (
	chcp 437 >nul
	schtasks /query /FO LIST /V > schtasks.txt || call :fail "schtasks /query"
	chcp %codepage% >nul
) else (
	schtasks /query /FO LIST /V > schtasks.txt || call :fail "schtasks /query"
)

:continue
rem wmic job list full /format:hform > WMIC_jobs.html
rem wmic qfe list > WMIC_Installed_KB.txt
rem wmic product list full /format:hform > WMIC_InstalledSoftwareList.html
rem wmic startup list full /format:hform > WMIC_startup.html
wmic process list full /format:hform > WMIC_process.html || call :fail "wmic process"
rem wmic service list full /format:hform > WMIC_services.html
wmic useraccount list full /format:hform > WMIC_user.html || call :fail "wmic useraccount"
rem wmic sysaccount list full /format:hform > WMIC_sysaccount.html
rem wmic group list full /format:hform > WMIC_group.html
wmic logon list full /format:hform > WMIC_logonlog.html || call :fail "wmic logon"
rem wmic netlogin list full /format:hform > WMIC_netloginlog.html

:: 新增wmic采集
wmic qfe list > WMIC_hotfixes.txt || call :fail "wmic qfe"

:: ============================================================
:: 新增 - 多用户遍历（解决仅采集当前用户的问题）
:: ============================================================
echo.
echo [*] Collecting per-user artifacts...
md Users
for /d %%U in (C:\Users\*) do (
    if /I not "%%~nxU"=="Public" (
    if /I not "%%~nxU"=="Default" (
    if /I not "%%~nxU"=="Default User" (
    if /I not "%%~nxU"=="All Users" (
        md ".\Users\%%~nxU" >nul 2>&1

        ::PowerShell命令历史
        xcopy /h/c/i "%%U\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" ".\Users\%%~nxU\PSHistory\" >nul 2>&1

        ::RDP客户端位图缓存及连接配置
        xcopy /e/h/c/i "%%U\AppData\Local\Microsoft\Terminal Server Client\Cache" ".\Users\%%~nxU\RDPBitmapCache" >nul 2>&1
        if exist "%%U\Documents\Default.rdp" copy /y "%%U\Documents\Default.rdp" ".\Users\%%~nxU\" >nul 2>&1

        ::Windows Timeline
        xcopy /e/h/c/i "%%U\AppData\Local\ConnectedDevicesPlatform" ".\Users\%%~nxU\ActivitiesCache" >nul 2>&1

        ::启动目录
        xcopy /e/h/c/i "%%U\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" ".\Users\%%~nxU\Startup" >nul 2>&1

        ::SSH密钥
        xcopy /e/h/c/i "%%U\.ssh" ".\Users\%%~nxU\SSH" >nul 2>&1

        ::Windows 11 Recall(回顾) 屏幕截图/活动库/向量库(Win11 24H2+)
        robocopy "%%U\AppData\Local\CoreAIPlatform.00\UKP" ".\Users\%%~nxU\Recall" /E /B /COPY:DAT /R:0 /W:0 >nul 2>&1

        ::远程控制软件痕迹(每用户: AnyDesk/TeamViewer/ToDesk)
        xcopy /e/h/c/i "%%U\AppData\Roaming\AnyDesk" ".\Users\%%~nxU\RemoteAccess\AnyDesk" >nul 2>&1
        xcopy /e/h/c/i "%%U\AppData\Roaming\TeamViewer" ".\Users\%%~nxU\RemoteAccess\TeamViewer" >nul 2>&1
        xcopy /e/h/c/i "%%U\AppData\Roaming\ToDesk" ".\Users\%%~nxU\RemoteAccess\ToDesk" >nul 2>&1

        ::浏览器历史文件（robocopy备份模式可绕过浏览器锁定）
        robocopy "%%U\AppData\Local\Google\Chrome\User Data\Default" ".\Users\%%~nxU\Browser\Chrome" History Cookies "Login Data" Downloads /B /COPY:DAT /R:0 /W:0 >nul 2>&1
        robocopy "%%U\AppData\Local\Microsoft\Edge\User Data\Default" ".\Users\%%~nxU\Browser\Edge" History Cookies "Login Data" Downloads /B /COPY:DAT /R:0 /W:0 >nul 2>&1
        xcopy /e/h/c/i "%%U\AppData\Roaming\Mozilla\Firefox\Profiles" ".\Users\%%~nxU\Browser\Firefox\" >nul 2>&1

        ::UsrClass.dat Shellbags（已删除文件夹的访问记录仍留存）
        robocopy "%%U\AppData\Local\Microsoft\Windows" ".\Users\%%~nxU\ShellBags" UsrClass.dat /B /COPY:DAT /R:0 /W:0 >nul 2>&1

        ::加载NTUSER.DAT导出各用户注册表项（仅对未登录用户生效，已登录用户hive被锁）
        reg load "HKU\ForensicTemp_%%~nxU" "%%U\NTUSER.DAT" >nul 2>&1
        if !errorlevel! == 0 (
            reg export "HKU\ForensicTemp_%%~nxU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"         ".\Users\%%~nxU\REG_UserAssist.txt" >nul 2>&1
            reg export "HKU\ForensicTemp_%%~nxU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"             ".\Users\%%~nxU\REG_RunMRU.txt" >nul 2>&1
            reg export "HKU\ForensicTemp_%%~nxU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"         ".\Users\%%~nxU\REG_RecentDocs.txt" >nul 2>&1
            reg export "HKU\ForensicTemp_%%~nxU\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2"       ".\Users\%%~nxU\REG_MountPoints2.txt" >nul 2>&1
            reg export "HKU\ForensicTemp_%%~nxU\Software\Microsoft\Windows\CurrentVersion\Run"                        ".\Users\%%~nxU\REG_Run.txt" >nul 2>&1
            reg export "HKU\ForensicTemp_%%~nxU\Software\Microsoft\Terminal Server Client\Servers"                    ".\Users\%%~nxU\REG_RDPServers.txt" >nul 2>&1
            reg export "HKU\ForensicTemp_%%~nxU\Software\Classes\CLSID"                                               ".\Users\%%~nxU\REG_COM_Hijack.txt" >nul 2>&1
            reg export "HKU\ForensicTemp_%%~nxU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32"          ".\Users\%%~nxU\REG_LastVisitedMRU.txt" >nul 2>&1
            reg export "HKU\ForensicTemp_%%~nxU\Software\Microsoft\Internet Explorer\TypedURLs"                       ".\Users\%%~nxU\REG_IETypedURLs.txt" >nul 2>&1
            reg unload "HKU\ForensicTemp_%%~nxU" >nul 2>&1
        )
    )
    )
    )
    )
)

:: ============================================================
:: 固证 chain-of-custody：对全部产物逐文件 SHA256 + 清单 + 清单根哈希
:: 用内置 certutil（NT6 全版本自带，无外部依赖）；任何文件改动→其哈希变→清单变→根哈希变。
:: 须在所有采集动作之后、目录不再变动时执行。
:: ============================================================
echo.
echo [*] Computing SHA256 chain-of-custody manifest...please wait
set "MANIFEST=_HASH_MANIFEST.txt"
> "%MANIFEST%" echo WinInfoSC Forensic Collection - SHA256 Manifest
>> "%MANIFEST%" echo Host=%NAME% IP=%IP% Generated=%DATE% %TIME%
>> "%MANIFEST%" echo ================================================
for /r %%F in (*) do (
    if /I not "%%~nxF"=="%MANIFEST%" (
        for /f "delims=" %%H in ('certutil -hashfile "%%F" SHA256 ^| findstr /v ":"') do (
            >> "%MANIFEST%" echo %%H  %%~fF
        )
    )
)
:: 清单根哈希（单一完整性锚点）
for /f "delims=" %%R in ('certutil -hashfile "%MANIFEST%" SHA256 ^| findstr /v ":"') do set "ROOT=%%R"
>> "%MANIFEST%" echo ================================================
>> "%MANIFEST%" echo MANIFEST_ROOT_SHA256=%ROOT%

cls
echo.
echo.
echo [*] Info gathering Finished.
echo [*] Chain-of-custody manifest: %MANIFEST%  (root SHA256=%ROOT%)
:: 统计失败命令数（"] FAIL " 仅匹配 :fail 子程序写入的记录行，不含日志头部）
set "FAILCOUNT=0"
for /f %%C in ('findstr /C:"] FAIL " "%FAILLOG%" 2^>nul ^| find /c /v ""') do set "FAILCOUNT=%%C"
if %FAILCOUNT% GTR 0 (
    color 0e
    echo [!] %FAILCOUNT% 条主干命令执行失败, 详见 _COLLECT_ERRORS.log
) else (
    echo [*] 主干命令全部执行成功, 无失败记录。
)
echo.
echo 请查看文件中的取证信息 Forensic_%IP%_%NAME%
echo Thank you~ Bye....
pause >nul
exit /b 0

:: ============================================================
:: 子程序：记录一条命令失败（由 "命令 || call :fail 标签" 触发）
:: ============================================================
:fail
>> "%FAILLOG%" echo [%TIME%] FAIL (exit=%errorlevel%) %~1
exit /b 0
