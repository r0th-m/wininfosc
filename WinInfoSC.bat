@echo off
color 0b
@echo ***************************************************************
echo.
echo                       W I N I N F O S C
echo              Windows Host Forensic Collector
echo                           by ye-mengwen
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

:: ============================================================
:: 采集端足迹自报告：记录采集过程执行的关键外部命令（时间<TAB>命令行，本地时间）
:: 供分析端 collector footprint 标注优先消费；先写 bat 同目录，建好输出目录后移入（与 _HASH_MANIFEST.txt 同级）
:: certutil 批量固证属固证动作非排查命令，只记一条汇总（明细见 _HASH_MANIFEST.txt），不逐条记录
:: ============================================================
set "FPLOG=%~dp0_COLLECT_FOOTPRINT.txt"
> "%FPLOG%" echo WinInfoSC Collector Footprint v1.0 - 采集端执行命令自报告
>> "%FPLOG%" echo Format: YYYY-MM-DD HH:MM:SS [TAB] CommandLine

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
        call :fp "%EVERYTHING_EXE% -instance Forensic （建立便携索引）"
        start "" "%~dp0%EVERYTHING_EXE%" -instance Forensic
        :: 等命名实例启动+建索引就绪(否则 es.exe 报 Error 8: IPC window not found)
        ping -n 12 127.0.0.1 >nul 2>&1
        call :fp "es.exe -instance Forensic -export-efu everything.efu"
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
for /f "delims=" %%i in ('hostname') do (
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

:: 足迹文件移入采集输出目录（与 _HASH_MANIFEST.txt 同级），并补写主机头
move /y "%~dp0_COLLECT_FOOTPRINT.txt" "%CD%\_COLLECT_FOOTPRINT.txt" >nul 2>&1
set "FPLOG=%CD%\_COLLECT_FOOTPRINT.txt"
>> "%FPLOG%" echo Host=%NAME% IP=%IP% Generated=%DATE% %TIME%

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
call :fp "w32tm /tz"
w32tm /tz >> _COLLECTION_TIME.txt 2>nul
:: w32tm /tz 在无夏令时规则的时区会报 TIME_ZONE_ID_UNKNOWN，补 tzutil /g 输出规范时区名（如 China Standard Time）
call :fp "tzutil /g"
for /f "delims=" %%Z in ('tzutil /g 2^>nul') do >> _COLLECTION_TIME.txt echo tzutil /g: %%Z
:: Win7(6.1) 无 tzutil,注册表兜底时区名(老机优雅降级,不记失败)
if errorlevel 1 (
  for /f "tokens=2*" %%A in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" /v TimeZoneKeyName 2^>/dev/null ^| findstr TimeZoneKeyName') do >> _COLLECTION_TIME.txt echo tz_keyname: %%B
)
call :fp "tasklist /V /FO CSV"
tasklist /V /FO CSV > tasklist_process.csv || call :fail "tasklist /V"
call :fp "tasklist /SVC /FO CSV"
tasklist /SVC /FO CSV > tasklist_services.csv || call :fail "tasklist /SVC"
call :fp "netstat -abon"
netstat -abon >> netstat.txt || call :fail "netstat -abon"
call :fp "netstat -aon | FIND 'ESTABLISHED'"
netstat -aon | FIND "ESTABLISHED" > netstat_established.txt
call :fp "ipconfig /displaydns"
ipconfig /displaydns > dns_cache.txt || call :fail "ipconfig /displaydns"
call :fp "arp -a"
arp -a > arp_a.txt || call :fail "arp -a"
call :fp "nbtstat -S"
nbtstat -S > nbtstat_cache.txt || call :fail "nbtstat -S"
call :fp "net session"
net session > net_session.txt || call :fail "net session"
call :fp "net use"
net use > net_use.txt || call :fail "net use"
:: USN 变更日志(文件系统增删改流水,含已删文件痕迹) —— 亦属易失
call :fp "fsutil usn readjournal C: csv"
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
    call :fp "%RAWCOPY_EXE% /FileNamePath:C:0 （采集 $MFT）"
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
call :fp "reg export  'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache' REG_Shimcache.txt"
reg export  "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" REG_Shimcache.txt || call :fail "reg Shimcache"
call :fp "reg export  'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist' REG_UserAssit.txt"
reg export  "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist" REG_UserAssit.txt || call :fail "reg UserAssist"
call :fp "reg export  'HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'  REG_IFEO.txt"
reg export  "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"  REG_IFEO.txt || call :fail "reg IFEO"
call :fp "reg export  'HKLM\Software\Microsoft\Windows\CurrentVersion\Run'  REG_CurrentVersionRun.txt"
reg export  "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"  REG_CurrentVersionRun.txt || call :fail "reg HKLM Run"
call :fp "reg export  'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects'  REG_BHO.txt"
reg export  "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"  REG_BHO.txt || call :fail "reg BHO"
call :fp "reg export  'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks'   REG_ShellExecuteHooks.txt"
reg export  "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks"   REG_ShellExecuteHooks.txt || call :fail "reg ShellExecuteHooks"
call :fp "reg export  'HKLM\SYSTEM\CurrentControlSet\Services'  REG_CurrentControlSet_Services.txt"
reg export  "HKLM\SYSTEM\CurrentControlSet\Services"  REG_CurrentControlSet_Services.txt || call :fail "reg Services"
call :fp "reg export  'HKLM\SYSTEM\ControlSet001\Services'  REG_ControlSet001_Services.txt"
reg export  "HKLM\SYSTEM\ControlSet001\Services"  REG_ControlSet001_Services.txt || call :fail "reg ControlSet001 Services"
call :fp "reg export  'HKLM\SYSTEM\ControlSet002\Services'  REG_ControlSet002_Services.txt"
reg export  "HKLM\SYSTEM\ControlSet002\Services"  REG_ControlSet002_Services.txt || call :fail "reg ControlSet002 Services"
call :fp "reg export  'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU' REG_RunMRU.txt"
reg export  "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" REG_RunMRU.txt || call :fail "reg RunMRU"
call :fp "reg export  'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs' REG_RecentDocs.txt"
reg export  "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" REG_RecentDocs.txt || call :fail "reg RecentDocs"

:: ============================================================
:: 注册表采集 - 新增：持久化机制
:: ============================================================
:: Winlogon - Shell/Userinit劫持
call :fp "reg export  'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'  REG_Winlogon.txt"
reg export  "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"  REG_Winlogon.txt 2>nul
:: AppInit_DLLs - 加载每个user-mode进程的DLL
call :fp "reg export  'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'  REG_AppInitDLLs.txt"
reg export  "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"  REG_AppInitDLLs.txt 2>nul
:: BootExecute - 开机最早执行阶段
call :fp "reg export  'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager'  REG_SessionManager.txt"
reg export  "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager"  REG_SessionManager.txt 2>nul
:: LSA - SSP注入、WDigest明文凭据开关
call :fp "reg export  'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'  REG_LSA.txt"
reg export  "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"  REG_LSA.txt 2>nul
:: COM劫持 - HKCU优先于HKLM加载，无需管理员权限
call :fp "reg export  'HKCU\Software\Classes\CLSID'  REG_COM_Hijack_HKCU.txt"
reg export  "HKCU\Software\Classes\CLSID"  REG_COM_Hijack_HKCU.txt 2>nul
:: 用户级Run键
call :fp "reg export  'HKCU\Software\Microsoft\Windows\CurrentVersion\Run'  REG_HKCU_Run.txt"
reg export  "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"  REG_HKCU_Run.txt 2>nul

:: ============================================================
:: 注册表采集 - 新增：USB设备接入历史
:: ============================================================
call :fp "reg export  'HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR'  REG_USBSTOR.txt"
reg export  "HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR"  REG_USBSTOR.txt 2>nul
call :fp "reg export  'HKLM\SYSTEM\CurrentControlSet\Enum\USB'  REG_USB.txt"
reg export  "HKLM\SYSTEM\CurrentControlSet\Enum\USB"  REG_USB.txt 2>nul
call :fp "reg export  'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2'  REG_MountPoints2.txt"
reg export  "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2"  REG_MountPoints2.txt 2>nul

:: ============================================================
:: 注册表采集 - 新增：RDP客户端历史
:: ============================================================
call :fp "reg export  'HKCU\Software\Microsoft\Terminal Server Client\Servers'  REG_RDPServers.txt"
reg export  "HKCU\Software\Microsoft\Terminal Server Client\Servers"  REG_RDPServers.txt 2>nul
call :fp "reg export  'HKCU\Software\Microsoft\Terminal Server Client\Default'   REG_RDPDefault.txt"
reg export  "HKCU\Software\Microsoft\Terminal Server Client\Default"   REG_RDPDefault.txt 2>nul

:: ============================================================
:: 注册表采集 - 新增：网络历史
:: ============================================================
call :fp "reg export  'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles'    REG_NetworkProfiles.txt"
reg export  "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles"    REG_NetworkProfiles.txt 2>nul
call :fp "reg export  'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures'  REG_NetworkSignatures.txt"
reg export  "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures"  REG_NetworkSignatures.txt 2>nul

:: ============================================================
:: 注册表采集 - 新增：Windows Defender排除项（攻击者常写入白名单）
:: ============================================================
call :fp "reg export  'HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions'  REG_DefenderExclusions.txt"
reg export  "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions"  REG_DefenderExclusions.txt 2>nul
call :fp "reg export  'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender'     REG_DefenderPolicy.txt"
reg export  "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender"     REG_DefenderPolicy.txt 2>nul
:: ============================================================
:: 驻留面扩展(2026-08-11, 对账 RogueCleaner 覆盖面):
:: Shell 扩展链/Native Messaging/浏览器扩展策略/文件关联 + 签名对账
:: ============================================================
call :fp "Shell 扩展/右键菜单链(ContextMenuHandlers/ShellExtensions/shellex)"
reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ContextMenuHandlers" REG_ContextMenuHandlers_HKLM.txt 2>nul
reg export "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ContextMenuHandlers" REG_ContextMenuHandlers_HKCU.txt 2>nul
reg export "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\ContextMenuHandlers" REG_ContextMenuHandlers_WOW64.txt 2>nul
reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions" REG_ShellExtensions_HKLM.txt 2>nul
reg export "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions" REG_ShellExtensions_HKCU.txt 2>nul
reg export "HKLM\SOFTWARE\Classes\Directory\Background\shellex\ContextMenuHandlers" REG_Shellex_DirBackground.txt 2>nul
reg export "HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers" REG_Shellex_Directory.txt 2>nul
reg export "HKLM\SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers" REG_Shellex_Folder.txt 2>nul
reg export "HKLM\SOFTWARE\Classes\Drive\shellex\ContextMenuHandlers" REG_Shellex_Drive.txt 2>nul
call :fp "Native Messaging Hosts(Chrome/Edge/Firefox)"
reg export "HKLM\SOFTWARE\Google\Chrome\NativeMessagingHosts" REG_NMH_Chrome_HKLM.txt 2>nul
reg export "HKCU\SOFTWARE\Google\Chrome\NativeMessagingHosts" REG_NMH_Chrome_HKCU.txt 2>nul
reg export "HKLM\SOFTWARE\WOW6432Node\Google\Chrome\NativeMessagingHosts" REG_NMH_Chrome_WOW64.txt 2>nul
reg export "HKLM\SOFTWARE\Microsoft\Edge\NativeMessagingHosts" REG_NMH_Edge_HKLM.txt 2>nul
reg export "HKCU\SOFTWARE\Microsoft\Edge\NativeMessagingHosts" REG_NMH_Edge_HKCU.txt 2>nul
reg export "HKLM\SOFTWARE\Mozilla\NativeMessagingHosts" REG_NMH_Firefox_HKLM.txt 2>nul
reg export "HKCU\SOFTWARE\Mozilla\NativeMessagingHosts" REG_NMH_Firefox_HKCU.txt 2>nul
call :fp "浏览器扩展策略(ExtensionForcelist/ExtensionSettings/Firefox Policies)"
reg export "HKLM\SOFTWARE\Policies\Google\Chrome" REG_ExtPolicy_Chrome_HKLM.txt 2>nul
reg export "HKCU\SOFTWARE\Policies\Google\Chrome" REG_ExtPolicy_Chrome_HKCU.txt 2>nul
reg export "HKLM\SOFTWARE\Policies\Microsoft\Edge" REG_ExtPolicy_Edge_HKLM.txt 2>nul
reg export "HKCU\SOFTWARE\Policies\Microsoft\Edge" REG_ExtPolicy_Edge_HKCU.txt 2>nul
reg export "HKLM\SOFTWARE\Policies\Mozilla\Firefox" REG_ExtPolicy_Firefox_HKLM.txt 2>nul
reg export "HKCU\SOFTWARE\Policies\Mozilla\Firefox" REG_ExtPolicy_Firefox_HKCU.txt 2>nul
call :fp "文件关联(FileExts 全量: UserChoice/OpenWith 残留)"
reg export "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts" REG_FileExts.txt 2>nul
call :fp "签名对账+shellex通配枚举(collect_ext.ps1 → signatures.csv/REG_Shellex_ClassesAll.txt)"
if exist "%~dp0collect_ext.ps1" powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0collect_ext.ps1" 2>nul


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
call :fp "reg export  'HKCU\Software\Microsoft\Windows\ShellNoRoam\MUICache' REG_MuiCache.txt"
reg export  "HKCU\Software\Microsoft\Windows\ShellNoRoam\MUICache" REG_MuiCache.txt
goto :MoreInfo

:NT6
::for vista 7 8 8.1 10
xcopy /e/h/c/i %SYSTEMROOT%\System32\winevt\Logs  .\Windows_logs\
:: EVTX capacity snapshot: sizes + per-channel oldest record time
call :fp "dir winevt Logs sizes -> evtx_sizes.txt"
dir /a /-c "%SYSTEMROOT%\System32\winevt\Logs\*.evtx" > evtx_sizes.txt 2>nul || call :fail "dir evtx sizes"
call :fp "powershell Get-WinEvent ListLog -> evtx_channel_stats.txt"
powershell -NoProfile -Command "try { Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | ForEach-Object { $oldest=''; try { $oldest=(Get-WinEvent -LogName $_.LogName -MaxEvents 1 -Oldest -ErrorAction Stop).TimeCreated.ToString('o') } catch {}; '{0}|Records={1}|Oldest={2}' -f $_.LogName, $_.RecordCount, $oldest } } catch { exit 1 }" > evtx_channel_stats.txt 2>nul
if errorlevel 1 >> "%FAILLOG%" echo [%TIME%] NOTE PowerShell Get-WinEvent unavailable, only evtx_sizes.txt collected
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
call :fp "reg export  'HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache' REG_MuiCache.txt"
reg export  "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache" REG_MuiCache.txt
::win10 only
call :fp "reg export  'HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings' REG_UserSettings.txt"
reg export  "HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings" REG_UserSettings.txt
::Amcache.hve 常被系统占用 → robocopy 备份模式绕锁（与其它 hive 取法一致）
if exist "%SYSTEMROOT%\AppCompat\Programs\Amcache.hve" (
    call :fp "esentutl /y AppCompat/Programs/Amcache.hve"
    esentutl /y "%SYSTEMROOT%\AppCompat\Programs\Amcache.hve" /d .\Amcache.hve /o >nul 2>&1
    if errorlevel 1 (
        robocopy "%SYSTEMROOT%\AppCompat\Programs" . Amcache.hve /B /COPY:DAT /R:0 /W:0 >nul 2>&1
        if not exist .\Amcache.hve call :fail "collect Amcache.hve"
    )
) else (
    >> "%FAILLOG%" echo [%TIME%] NOTE Amcache.hve absent ^(old OS or disabled^), skip
)

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
call :fp "reg export 'HKCU\Software\Policies\Microsoft\Windows\WindowsAI' REG_Recall_WindowsAI_HKCU.txt"
reg export "HKCU\Software\Policies\Microsoft\Windows\WindowsAI" REG_Recall_WindowsAI_HKCU.txt 2>nul
call :fp "reg export 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' REG_Recall_WindowsAI_HKLM.txt"
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
call :fp "ipconfig /all"
ipconfig /all  > ipconfig.txt || call :fail "ipconfig /all"
call :fp "systeminfo"
systeminfo > systeminfo.txt || call :fail "systeminfo"
call :fp "net share"
net share > net_share.txt || call :fail "net share"
call :fp "net user"
net user > net_user.txt || call :fail "net user"
call :fp "net user Administrator"
net user Administrator >net_user_Administrator.txt || call :fail "net user Administrator"
:: All local accounts detail incl LastPasswordSet (delims= keeps space-names)
call :fp "net user all accounts detail -> net_user_all.txt"
(for /f "delims=" %%u in ('net user ^| findstr /v /c:"命令成功完成" /c:"User accounts" /c:"----"') do @net user %%u) > net_user_all.txt 2>nul || call :fail "net user all accounts detail"
::如非域环境net view过于影响脚本性能，默认注释。
::net view > net_view.txt
call :fp "cmdkey /l"
cmdkey /l >cmdkey.txt || call :fail "cmdkey /l"
call :fp "netsh advfirewall firewall show rule name=all"
netsh advfirewall firewall show rule name=all >netsh_firewall_all.txt || call :fail "netsh firewall rules"
call :fp "netsh interface portproxy show all"
netsh interface portproxy show all >netsh_portproxy_all.txt || call :fail "netsh portproxy"
call :fp "route print"
route print >route_print.txt || call :fail "route print"
call :fp "net localgroup"
net localgroup > net_localgroup.txt || call :fail "net localgroup"
call :fp "net localgroup administrators"
net localgroup administrators > net_localgroup_admin.txt || call :fail "net localgroup administrators"
call :fp "regedit /e .\regedit.reg"
regedit /e .\regedit.reg || call :fail "regedit /e"
dir /TC /AH %SYSTEMROOT%\System32 > dir_system32_hide.txt
dir /tc /q /a %SYSTEMROOT%\Fonts | findstr /v /i "\.fon \.ttf \.ttc \.otf \. \.. \.CompositeFont desktop\.ini fms_metadata\.xml StaticCache\.dat" > dir_fonts.txt

:: ============================================================
:: 新增 - 网络补充
:: ============================================================
::Wi-Fi历史及明文密码（netsh wlan export需要有无线网卡）
call :fp "netsh wlan show profiles"
netsh wlan show profiles > wifi_profiles.txt 2>nul
call :fp "netsh wlan export profile folder=.\WiFiProfiles key=clear"
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
call :fp "auditpol /get /category:*"
auditpol /get /category:* > auditpol.txt 2>nul

::凭据保险箱
call :fp "vaultcmd /listcreds:'Windows Credentials' /all"
vaultcmd /listcreds:"Windows Credentials" /all > vault_creds.txt 2>nul
call :fp "vaultcmd /listcreds:'Web Credentials' /all"
vaultcmd /listcreds:"Web Credentials" /all >> vault_creds.txt 2>nul

::驱动列表
call :fp "driverquery /FO CSV /V"
driverquery /FO CSV /V > driverquery.csv || call :fail "driverquery"

::VSS卷影副本枚举（判断攻击者是否已删除）
call :fp "vssadmin list shadows"
vssadmin list shadows > vss_shadows.txt 2>nul
call :fp "vssadmin list shadowstorage"
vssadmin list shadowstorage >> vss_shadows.txt 2>nul

::BITS后台传输作业（隐蔽下载/持久化）
call :fp "bitsadmin /list /allusers /verbose"
bitsadmin /list /allusers /verbose > bits_jobs.txt 2>nul

::回收站元数据（$I文件含原始路径和删除时间）
dir /a /s C:\$Recycle.Bin > recycle_bin_list.txt 2>nul

::IIS日志（如有IIS）
xcopy /e/h/c/i "%SystemRoot%\System32\LogFiles\W3SVC1" .\IIS_Logs\ >nul 2>&1

:: ============================================================
:: 新增 - WMI持久化订阅（无文件后门核心手段，原生wmic可查）
:: ============================================================
md WMI_Subscription
call :fp "wmic /namespace:\\root\subscription PATH __EventFilter GET * /format:list"
wmic /namespace:\\root\subscription PATH __EventFilter GET * /format:list > .\WMI_Subscription\EventFilter.txt 2>nul
call :fp "wmic /namespace:\\root\subscription PATH __EventConsumer GET * /format:list"
wmic /namespace:\\root\subscription PATH __EventConsumer GET * /format:list > .\WMI_Subscription\EventConsumer.txt 2>nul
call :fp "wmic /namespace:\\root\subscription PATH __FilterToConsumerBinding GET * /format:list"
wmic /namespace:\\root\subscription PATH __FilterToConsumerBinding GET * /format:list > .\WMI_Subscription\FilterToConsumerBinding.txt 2>nul

:: ============================================================
:: 新增 - SRUM数据库原始文件（esentutl可绕过ESE锁定）
:: ============================================================
call :fp "esentutl /y '%SystemRoot%\System32\sru\SRUDB.dat' /d .\SRUDB.dat /o"
esentutl /y "%SystemRoot%\System32\sru\SRUDB.dat" /d .\SRUDB.dat /o >nul 2>&1
:: Windows 搜索索引数据库(ESE) - 搜索历史/文件与邮件索引元数据(esentutl 绕 ESE 锁)
call :fp "esentutl /y '%ProgramData%\Microsoft\Search\Data\Applications\Windows\Windows.edb' /d .\Windows.edb /o"
esentutl /y "%ProgramData%\Microsoft\Search\Data\Applications\Windows\Windows.edb" /d .\Windows.edb /o >nul 2>&1
:: SOFTWARE hive二进制 - srum-dump -r 用于把AppID/网卡LUID反解为可读名
:: 采集时只有一次机会，须与SRUDB.dat同采，否则SRUM解析降级为裸数字
call :fp "reg save HKLM\SOFTWARE .\SOFTWARE /y"
reg save HKLM\SOFTWARE .\SOFTWARE /y >nul 2>&1
:: 传统四大 hive 二进制补齐(SAM=账户/哈希, SECURITY=LSA secrets, SYSTEM=服务/USB/网络)
call :fp "reg save HKLM\SAM .\SAM /y"
reg save HKLM\SAM .\SAM /y >nul 2>&1
call :fp "reg save HKLM\SECURITY .\SECURITY /y"
reg save HKLM\SECURITY .\SECURITY /y >nul 2>&1
call :fp "reg save HKLM\SYSTEM .\SYSTEM /y"
reg save HKLM\SYSTEM .\SYSTEM /y >nul 2>&1

:: ============================================================
:: UAL (User Access Log, ESE) - Server SKU default on.
:: Same esentutl /y trick as SRUDB.dat. Skip w/ note if absent.
:: ============================================================
if exist "%SYSTEMROOT%\System32\LogFiles\Sum\Current.mdb" (
    if not exist .\UAL md .\UAL
    call :fp "esentutl /y LogFiles/Sum/Current.mdb -> UAL/"
    esentutl /y "%SYSTEMROOT%\System32\LogFiles\Sum\Current.mdb" /d .\UAL\Current.mdb /o >nul 2>&1
    if errorlevel 1 call :fail "esentutl UAL Current.mdb"
    call :fp "esentutl /y LogFiles/Sum/SystemIdentity.mdb -> UAL/"
    esentutl /y "%SYSTEMROOT%\System32\LogFiles\Sum\SystemIdentity.mdb" /d .\UAL\SystemIdentity.mdb /o >nul 2>&1
    if errorlevel 1 call :fail "esentutl UAL SystemIdentity.mdb"
    call :fp "xcopy LogFiles/Sum/* -> UAL/ (mdb/jrs/log/chk sidecar)"
    xcopy /e/h/c/i "%SYSTEMROOT%\System32\LogFiles\Sum\*" .\UAL\ >nul 2>&1
) else (
    echo [!] UAL not present ^(non-Server SKU or UALSVC disabled^), skip
    >> "%FAILLOG%" echo [%TIME%] NOTE UAL not present - skipped ^(non-Server SKU or UALSVC disabled^)
)




:: 判断Win7/2008系统
for /f "tokens=1* delims=[" %%a in ('ver') do set b=%%b
set b=%b:* =%
set b=%b:~0,3%
if "%b%" == "6.1" (
	goto :win7only
) else (
	call :fp "schtasks /query /FO LIST /V"
	schtasks /query /FO LIST /V > schtasks.txt || call :fail "schtasks /query"
	goto :continue
)


:: 更改字符集
:win7only
for /f "tokens=2 delims=:" %%i in ('chcp') do set codepage=%%i
if "%codepage%" NEQ " 437" (
	chcp 437 >nul
	call :fp "schtasks /query /FO LIST /V"
	schtasks /query /FO LIST /V > schtasks.txt || call :fail "schtasks /query"
	chcp %codepage% >nul
) else (
	call :fp "schtasks /query /FO LIST /V"
	schtasks /query /FO LIST /V > schtasks.txt || call :fail "schtasks /query"
)

:continue
rem wmic job list full /format:hform > WMIC_jobs.html
rem wmic qfe list > WMIC_Installed_KB.txt
rem wmic product list full /format:hform > WMIC_InstalledSoftwareList.html
rem wmic startup list full /format:hform > WMIC_startup.html
call :fp "wmic process list full /format:hform"
wmic process list full /format:hform > WMIC_process.html 2>nul
if errorlevel 1 (
    :: wmic 不可用（新版 Windows 已弃用 wmic），用 tasklist 兜底采集进程视图
    >> "%FAILLOG%" echo [%TIME%] FAIL wmic process - wmic 不可用，已用 tasklist 兜底，exit=!errorlevel!
    call :fp "tasklist /V /FO LIST （wmic process 兜底）"
    tasklist /V /FO LIST > tasklist_process.txt 2>nul
)
rem wmic service list full /format:hform > WMIC_services.html
call :fp "wmic useraccount list full /format:hform"
wmic useraccount list full /format:hform > WMIC_user.html 2>nul
if errorlevel 1 (
    :: wmic 不可用；账户信息前面已由 net user 采集（net_user.txt），跳过兜底仅记录
    >> "%FAILLOG%" echo [%TIME%] FAIL wmic useraccount - wmic 不可用，账户信息已由 net user 采集（net_user.txt），跳过兜底，exit=!errorlevel!
)
rem wmic sysaccount list full /format:hform > WMIC_sysaccount.html
rem wmic group list full /format:hform > WMIC_group.html
call :fp "wmic logon list full /format:hform"
wmic logon list full /format:hform > WMIC_logonlog.html 2>nul
if errorlevel 1 (
    :: wmic 不可用，用 query user 兜底登录会话视图
    >> "%FAILLOG%" echo [%TIME%] FAIL wmic logon - wmic 不可用，已用 query user 兜底，exit=!errorlevel!
    call :fp "query user （wmic logon 兜底）"
    query user > query_user_logon.txt 2>nul
)
rem wmic netlogin list full /format:hform > WMIC_netloginlog.html

:: 新增wmic采集
call :fp "wmic qfe list"
wmic qfe list > WMIC_hotfixes.txt 2>nul
if errorlevel 1 (
    :: wmic 不可用，从已采集的 systeminfo.txt 提取修补程序列表兜底
    >> "%FAILLOG%" echo [%TIME%] FAIL wmic qfe - wmic 不可用，已从 systeminfo.txt 提取修补程序兜底，exit=!errorlevel!
    call :fp "findstr KB systeminfo.txt （wmic qfe 兜底）"
    findstr /i "KB" systeminfo.txt > qfe_from_systeminfo.txt 2>nul
)

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

        ::credential stores (NetSarang/MobaXterm/WinSCP) + RustDesk/Sunlogin
        xcopy /e/h/c/i "%%U\Documents\NetSarang" ".\Users\%%~nxU\CredStore\NetSarang" >nul 2>&1
        xcopy /e/h/c/i "%%U\Documents\MobaXterm" ".\Users\%%~nxU\CredStore\MobaXterm" >nul 2>&1
        if exist "%%U\AppData\Roaming\WinSCP.ini" copy /y "%%U\AppData\Roaming\WinSCP.ini" ".\Users\%%~nxU\CredStore\" >nul 2>&1
        if exist "%%U\AppData\Roaming\MobaXterm" xcopy /e/h/c/i "%%U\AppData\Roaming\MobaXterm" ".\Users\%%~nxU\CredStore\MobaXterm-roaming" >nul 2>&1
        xcopy /e/h/c/i "%%U\AppData\Roaming\RustDesk" ".\Users\%%~nxU\RemoteAccess\RustDesk" >nul 2>&1
        xcopy /e/h/c/i "%%U\AppData\Roaming\SunloginClient" ".\Users\%%~nxU\RemoteAccess\SunloginClient" >nul 2>&1
        :: Sunlogin real log home (verified 2026-08-04): %APPDATA%\Oray\{AweSun,SunloginClient}
        xcopy /e/h/c/i "%%U\AppData\Roaming\Oray" ".\Users\%%~nxU\RemoteAccess\Oray" >nul 2>&1
        ::浏览器历史文件（robocopy备份模式可绕过浏览器锁定）
        for /d %%P in ("%%U\AppData\Local\Google\Chrome\User Data\*") do robocopy "%%P" ".\Users\%%~nxU\Browser\Chrome\%%~nxP" History Cookies "Login Data" Downloads /B /COPY:DAT /R:0 /W:0 >nul 2>&1
        for /d %%P in ("%%U\AppData\Local\Microsoft\Edge\User Data\*") do robocopy "%%P" ".\Users\%%~nxU\Browser\Edge\%%~nxP" History Cookies "Login Data" Downloads /B /COPY:DAT /R:0 /W:0 >nul 2>&1
        xcopy /e/h/c/i "%%U\AppData\Roaming\Mozilla\Firefox\Profiles" ".\Users\%%~nxU\Browser\Firefox\" >nul 2>&1
        if exist "%%U\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat" esentutl /y "%%U\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat" /d ".\Users\%%~nxU\Browser\IE\WebCacheV01.dat" /o >nul 2>&1

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
:: Navicat saved connections (HKCU, current collecting user only)
call :fp "reg export HKCU/Software/PremiumSoft Navicat.reg"
reg export "HKCU\Software\PremiumSoft" Navicat.reg >nul 2>&1
if errorlevel 1 >> "%FAILLOG%" echo [%TIME%] NOTE no HKCU PremiumSoft ^(no Navicat^), skip

echo [*] Computing SHA256 chain-of-custody manifest...please wait
set "MANIFEST=_HASH_MANIFEST.txt"
> "%MANIFEST%" echo WinInfoSC Forensic Collection - SHA256 Manifest
>> "%MANIFEST%" echo Host=%NAME% IP=%IP% Generated=%DATE% %TIME%
>> "%MANIFEST%" echo ================================================
:: 足迹：certutil 批量固证只记一条汇总（逐文件明细即本清单）
:: manifest via PowerShell .NET SHA256 (Win7 cmd 6.1 nested-FOR "do was unexpected" workaround)
set "FPCOUNT=0"
for /r %%F in (*) do set /a FPCOUNT+=1
call :fp "manifest(PS .NET SHA256) %FPCOUNT% files"
set "MNAME=_HASH_MANIFEST.txt"
powershell -NoProfile -Command "$sha=[System.Security.Cryptography.SHA256]::Create(); Get-ChildItem -Recurse -File | Where-Object { $_.Name -ne $env:MNAME } | ForEach-Object { $fs=[System.IO.File]::OpenRead($_.FullName); $h=($sha.ComputeHash($fs) | ForEach-Object { $_.ToString('x2') }) -join ''; $fs.Close(); ($h.ToLower() + '  ' + $_.FullName) }" >> "%MANIFEST%" 2>nul
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

:: ============================================================
:: 子程序：记录一条采集足迹（时间(YYYY-MM-DD HH:MM:SS)<TAB>命令行）
:: 优先用 PowerShell 取标准时间格式；无 PowerShell 时退化为 %DATE% %TIME%
:: 用 !FP_CMD! 延迟扩展输出，避免命令行中的 | 等字符被当成管道符
:: ============================================================
:fp
set "FP_CMD=%~1"
set "FP_TS=%DATE% %TIME:~0,8%"
for /f "delims=" %%T in ('powershell -NoProfile -Command "Get-Date -Format yyyy-MM-dd_HH:mm:ss" 2^>nul') do set "FP_TS=%%T"
set "FP_TS=%FP_TS:_= %"
>> "%FPLOG%" echo !FP_TS!	!FP_CMD!
exit /b 0
