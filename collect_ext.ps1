# WinInfoSC 驻留面扩展采集(2026-08-11, 对账 RogueCleaner 覆盖面):
# ① HKLM\SOFTWARE\Classes\*\shellex\ContextMenuHandlers 通配枚举(reg.exe 不支持通配)
# ② 驻留项二进制 Authenticode 签名对账(services ImagePath + Run/RunOnce)
# 输出到当前目录: REG_Shellex_ClassesAll.txt / signatures.csv
# 只读,零修改;任何单项失败不拖垮整体(尽力而为,缺口如实落 _COLLECT_ERRORS 由主脚本管)。
# 兼容:PowerShell 2.0+(Win7/2008R2 起,含 Win10/11/Server 全系);XP/2003 无 PowerShell,主脚本静默跳过。
$ErrorActionPreference = 'SilentlyContinue'

# ---- ① shellex ContextMenuHandlers 全类通配枚举 ----
# 教训(2026-08-11 实测):PS 提供程序通配 Get-ChildItem 'HKLM:\SOFTWARE\Classes\*'
# 会遍历整个 Classes 键(数万子键),卡死分钟级;改 Win32 Registry API 直读,秒级。
$out = New-Object 'System.Collections.Generic.List[string]'   # PS2.0 兼容(Win7/2008R2 自带 PS2.0 无 ::new)
$classes = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\Classes')
if ($null -ne $classes) {
    foreach ($progid in $classes.GetSubKeyNames()) {
        $cmh = $classes.OpenSubKey("$progid\shellex\ContextMenuHandlers")
        if ($null -eq $cmh) { continue }
        foreach ($handler in $cmh.GetSubKeyNames()) {
            $h = $cmh.OpenSubKey($handler)
            $clsid = $h.GetValue('')
            $out.Add("HKLM\SOFTWARE\Classes\$progid\shellex\ContextMenuHandlers\$handler`t$clsid")
            $h.Close()
        }
        $cmh.Close()
    }
    $classes.Close()
}
$out | Out-File -Encoding utf8 REG_Shellex_ClassesAll.txt

# ---- ② 签名对账 ----
$raw = @{}
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' | ForEach-Object {
    $v = (Get-ItemProperty $_.PSPath -Name ImagePath).ImagePath
    if ($v) { $raw[$v] = 1 }
}
$runKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
)
foreach ($r in $runKeys) {
    $item = Get-Item $r
    if ($null -eq $item) { continue }
    foreach ($name in $item.Property) {
        $v = (Get-ItemProperty $r -Name $name).$name
        if ($v) { $raw[[string]$v] = 1 }
    }
}

'path,status,signer' | Out-File -Encoding utf8 signatures.csv
$seen = @{}
foreach ($k in $raw.Keys) {
    # 从命令行里抽可执行路径(带引号/参数/环境变量的都归一)
    $m = [regex]::Match($k, '(?i)([a-z]:[\\/][^"<>|]+?\.(exe|dll|sys|com|bat|ps1))')
    if (-not $m.Success) { continue }
    $f = [Environment]::ExpandEnvironmentVariables($m.Groups[1].Value).Trim('"')
    if ($seen.ContainsKey($f)) { continue }
    $seen[$f] = 1
    if (-not (Test-Path $f)) { continue }
    $sg = Get-AuthenticodeSignature $f
    $subj = '-'
    if ($sg.SignerCertificate) { $subj = $sg.SignerCertificate.Subject }
    # RFC4180:字段加引号且内嵌引号翻倍(签名主题含 CN="..." 实测会撞)
    $esc = { param($v) '"' + ([string]$v -replace '"', '""') + '"' }
    (& $esc $f) + ',' + (& $esc $sg.Status) + ',' + (& $esc $subj) |
        Out-File -Encoding utf8 -Append signatures.csv
}
