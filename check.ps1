<#
.SYNOPSIS
    Compromise check for the "Bang luong" (Vietnamese payroll lure) campaign.
    Winos 4.0-style toolchain: WinRAR SFX -> WeChatAppEx sideloading (xweb_elf.dll)
    -> TG_Soft.sys kernel EDR-killer -> LuaJIT plugins (TGFile.exe) -> RAT.

.DESCRIPTION
    Read-only hunt for all host-side IOCs of this campaign:
      - Drop directory        C:\ProgramLog\Windows\AppData\Log
      - Known file hashes     (dropped payload files)
      - Scheduled tasks       "OneDirverUpdata" or any action referencing indicators
      - COM TypeLib hijack    {EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}\1.1\0\win64
      - Services / drivers    image path under C:\ProgramLog or named TG_Soft
      - Live processes        running from the drop path
      - Active C2             182.140.242.59:13444 (TCP)
      - Live mutexes          Global\TGFile_ShellcodeMutex, Local\TGFile_SetupMutex
      - Prefetch evidence     TGFILE-*.pf (retrospective, survives file deletion)
      - Autostart entries     Run keys / Startup folders referencing indicators

    Safe to run on any host: it only READS, changes nothing.
    Exit codes: 0 = clean, 1 = indicators found (useful for RMM/automation).

.PARAMETER Deep
    Optional slow sweep of the whole C:\ drive for known campaign filenames
    (takes minutes; catches dropped files outside the standard path).

.PARAMETER LogPath
    Optional path to save the report as a text file.

.EXAMPLE
    .\check.ps1
    .\check.ps1 -Deep -LogPath C:\temp\check-result.txt
#>

[CmdletBinding()]
param(
    [switch]$Deep,
    [string]$LogPath
)

$IndicatorRegex = 'ProgramLog|TGFile|TG_Soft|xweb_elf|hide\.log|regite\.log|set\.log|WeChatAppEx'
$C2Address      = '182.140.242.59'

$KnownHashes = @{
    'TGFile.exe'   = '09CD30B1B25DA3FF6661BE589D5C31460E51E9EE8E7925DF37826456BB8DA2BC'
    'TG_Soft.sys'  = '2451129AEDD9D7A60E7A35639E753FE79887AE075D65872181DEBB9ADBA69DAC'
    'xweb_elf.dll' = '734B6729731D85988627E84B01D22298C04378E4949C5E69C34237A4574F3DCB'
    'hide.log'     = '8B754733762658C0D8B2A4E8B5AD6A4A19BC56D18C0363E6A63FAD570C4A0ABF'
    'set.log'      = '1349D8BE2179AB1343F00D21D4A428E1794A5D844888C7B7D067CFF14270112A'
    'regite.log'   = '8FB2BD680E185BCE54529D506FFC67D4AFAE84A04791598B029EAF088D1A1F1C'
    'new.jpg'      = '16CFE3F43C4EEDF7F7DDCB9F8DB876DA80D4E58F0BDEAB878C49A590A2F33E12'
}

$Script:Findings = @()
$Script:Report   = @()

function Write-Ok {
    param([string]$Message)
    Write-Host "[OK] $Message" -ForegroundColor Green
    $Script:Report += "[OK] $Message"
}

function Write-Hit {
    param([string]$Message)
    Write-Host "[!!] $Message" -ForegroundColor Red
    $Script:Findings += $Message
    $Script:Report   += "[!!] $Message"
}

function Write-Note {
    param([string]$Message)
    Write-Host "[--] $Message" -ForegroundColor Yellow
    $Script:Report += "[--] $Message"
}

# ---------------------------------------------------------------- header
$Elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
            ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Write-Host ("=" * 70)
Write-Host ' "Bang luong" campaign - compromise check (read-only)'
Write-Host " Host: $env:COMPUTERNAME   User: $env:USERNAME   Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host ("=" * 70)
if ($Elevated) { Write-Note 'Running ELEVATED - full coverage.' }
else           { Write-Note 'NOT elevated - Prefetch check and some service paths may be silently skipped. Re-run elevated for full coverage.' }

# ---------------------------------------------------------------- 1. drop directory
if (Test-Path 'C:\ProgramLog') {
    Write-Hit 'Drop directory exists: C:\ProgramLog'
    Get-ChildItem 'C:\ProgramLog' -Recurse -File -ErrorAction SilentlyContinue |
        ForEach-Object {
            Write-Hit ("    File: {0}  {1} bytes  {2}" -f $_.FullName, $_.Length, $_.LastWriteTime)
        }
} else {
    Write-Ok 'Drop directory C:\ProgramLog not present'
}

# ---------------------------------------------------------------- 2. known hashes
$hashHits = 0
foreach ($f in $KnownHashes.Keys) {
    $p = Join-Path 'C:\ProgramLog\Windows\AppData\Log' $f
    if (Test-Path $p) {
        $hashHits++
        $h = (Get-FileHash $p -Algorithm SHA256).Hash
        if ($h -eq $KnownHashes[$f]) { Write-Hit "EXACT MATCH: $f ($h)" }
        else                         { Write-Hit "Present but hash differs (possible variant): $f ($h)" }
    }
}
if ($hashHits -eq 0) { Write-Ok 'No known campaign files present in drop path' }

# ---------------------------------------------------------------- 3. scheduled tasks
$taskHit = $false
try {
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
    foreach ($t in $tasks) {
        if ($t.TaskName -eq 'OneDirverUpdata') {
            Write-Hit ("Scheduled task 'OneDirverUpdata' -> {0} {1}" -f $t.Actions.Execute, $t.Actions.Arguments)
            $taskHit = $true
            continue
        }
        foreach ($a in $t.Actions) {
            $line = "$($a.Execute) $($a.Arguments)"
            if ($line -match 'ProgramLog|TGFile|hide\.log|set\.log|regite\.log') {
                Write-Hit ("Task '\{0}\{1}' references campaign indicators: {2}" -f $t.TaskPath, $t.TaskName, $line)
                $taskHit = $true
            }
        }
    }
} catch { Write-Note "Scheduled task sweep error: $($_.Exception.Message)" }
if (-not $taskHit) { Write-Ok 'No campaign-related scheduled tasks' }

# ---------------------------------------------------------------- 4. COM TypeLib hijack
$tlKey = 'HKLM:\SOFTWARE\Classes\TypeLib\{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}\1.1\0\win64'
if (Test-Path $tlKey) {
    $props = Get-ItemProperty $tlKey -ErrorAction SilentlyContinue
    $dirty = $props.PSObject.Properties | Where-Object { "$($_.Value)" -match 'ProgramLog|\.s\b' }
    if ($dirty) {
        foreach ($d in $dirty) {
            Write-Hit ("TypeLib hijack: {0} -> '{1}' = '{2}'" -f $tlKey, $d.Name, $d.Value)
        }
    } else {
        Write-Ok 'TypeLib key present (normal) but values clean'
    }
} else {
    Write-Ok 'TypeLib key not present'
}

# ---------------------------------------------------------------- 5. drivers & services
$svcHit = $false
Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue |
    Where-Object { $_.PathName -match 'ProgramLog|TG_Soft' -or $_.Name -match 'TG_Soft' } |
    ForEach-Object {
        Write-Hit ("Driver: {0} state={1} path={2}" -f $_.Name, $_.State, $_.PathName)
        $svcHit = $true
    }
Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
    Where-Object { $_.PathName -match 'ProgramLog|TGFile|WeChatAppEx|hide\.log|set\.log' } |
    ForEach-Object {
        Write-Hit ("Service: {0} state={1} path={2}" -f $_.Name, $_.State, $_.PathName)
        $svcHit = $true
    }
if (-not $svcHit) { Write-Ok 'No campaign services or drivers registered' }

# ---------------------------------------------------------------- 6. live processes
$procHit = $false
Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
    Where-Object { $_.ExecutablePath -like 'C:\ProgramLog*' } |
    ForEach-Object {
        Write-Hit ("Process running from drop path: {0} pid={1}" -f $_.ExecutablePath, $_.ProcessId)
        $procHit = $true
    }
Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -eq 'TGFile.exe' } |
    ForEach-Object {
        Write-Hit ("TGFile.exe running from ANY path: pid={0} path={1}" -f $_.ProcessId, $_.ExecutablePath)
        $procHit = $true
    }
if (-not $procHit) { Write-Ok 'No campaign processes running' }

# ---------------------------------------------------------------- 7. active C2
$c2Hit = $false
try {
    Get-NetTCPConnection -RemoteAddress $C2Address -ErrorAction SilentlyContinue |
        ForEach-Object {
            Write-Hit ("ACTIVE C2: {0}:{1} pid={2} state={3}" -f $_.RemoteAddress, $_.RemotePort, $_.OwningProcess, $_.State)
            $c2Hit = $true
        }
} catch { Write-Note "TCP check error (non-elevated?): $($_.Exception.Message)" }
if (-not $c2Hit) { Write-Ok "No active connection to C2 $C2Address" }

# ---------------------------------------------------------------- 8. live mutexes
$mutexHit = $false
foreach ($mn in @('Global\TGFile_ShellcodeMutex', 'Local\TGFile_SetupMutex')) {
    try {
        $m = [System.Threading.Mutex]::OpenExisting($mn)
        $m.Close()
        Write-Hit "Live mutex present: $mn (malware stage running NOW)"
        $mutexHit = $true
    } catch { }
}
if (-not $mutexHit) { Write-Ok 'No campaign mutexes present' }

# ---------------------------------------------------------------- 9. prefetch (retrospective)
$pfHit = $false
if ($Elevated -or (Test-Path 'C:\Windows\Prefetch')) {
    foreach ($pf in @('*TGFILE*', '*TG_SOFT*')) {
        Get-ChildItem 'C:\Windows\Prefetch' -Filter $pf -ErrorAction SilentlyContinue |
            ForEach-Object {
                Write-Hit ("Prefetch evidence: {0} (last run {1})" -f $_.Name, $_.LastWriteTime)
                $pfHit = $true
            }
    }
} else {
    Write-Note 'Prefetch folder not readable - check skipped'
}
if (-not $pfHit -and $Elevated) { Write-Ok 'No prefetch evidence' }

# ---------------------------------------------------------------- 10. autostart sweep
$autoHit = $false
$runKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
)
foreach ($rk in $runKeys) {
    if (Test-Path $rk) {
        $props = Get-ItemProperty $rk -ErrorAction SilentlyContinue
        foreach ($p in $props.PSObject.Properties) {
            if ("$($p.Value)" -match 'ProgramLog|TGFile|WeChatAppEx' -and $p.Name -notmatch '^PS') {
                Write-Hit ("Run key hit: {0}\{1} = {2}" -f $rk, $p.Name, $p.Value)
                $autoHit = $true
            }
        }
    }
}
foreach ($sf in @([Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup'))) {
    if ($sf -and (Test-Path $sf)) {
        Get-ChildItem $sf -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match 'TGFile|ProgramLog' } |
            ForEach-Object {
                Write-Hit "Startup folder hit: $($_.FullName)"
                $autoHit = $true
            }
    }
}
if (-not $autoHit) { Write-Ok 'Autostart entries clean' }

# ---------------------------------------------------------------- 11. optional deep sweep
if ($Deep) {
    Write-Note 'Deep sweep: scanning C:\ for campaign filenames (this takes a while)...'
    $deepHit = $false
    Get-ChildItem -Path 'C:\' -Recurse -Force -ErrorAction SilentlyContinue -Include @(
        'TGFile.exe', 'TG_Soft.sys', 'xweb_elf.dll', 'hide.log', 'regite.log', 'set.log'
    ) -File | ForEach-Object {
        Write-Hit "Deep sweep: $($_.FullName)"
        $deepHit = $true
    }
    if (-not $deepHit) { Write-Ok 'Deep sweep: no campaign filenames found on C:\' }
}

# ---------------------------------------------------------------- summary
Write-Host ("=" * 70)
if ($Script:Findings.Count -gt 0) {
    Write-Host ("RESULT: COMPROMISED / INDICATORS FOUND - {0} finding(s)" -f $Script:Findings.Count) -ForegroundColor Red
    Write-Host ' Recommended: isolate host, preserve memory + C:\ProgramLog, assume credential theft (keylogger active), hunt laterally.'
    $exit = 1
} else {
    Write-Host 'RESULT: CLEAN - no indicators of this campaign found.' -ForegroundColor Green
    Write-Host ' Note: this is a targeted hunt for this campaign only, not a general compromise assessment.'
    $exit = 0
}
Write-Host ("=" * 70)

if ($LogPath) {
    $Script:Report += "RESULT exit=$exit findings=$($Script:Findings.Count)"
    $Script:Report | Out-File -FilePath $LogPath -Encoding UTF8
    Write-Host "Report saved to $LogPath"
}

exit $exit
