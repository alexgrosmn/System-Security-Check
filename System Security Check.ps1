# ================================================================
# Windows VBS Security Stack Checker v3
# Requires: Run as Administrator
# ================================================================
 
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host ''
    Write-Host '  This script requires Administrator privileges.' -ForegroundColor Red
    Write-Host '  Right-click the script (or your PowerShell shortcut) and choose "Run as Administrator".' -ForegroundColor Yellow
    Write-Host ''
    Read-Host '  Press Enter to close'
    exit
}
 
Write-Host ''
Write-Host '  Choose a scan type:' -ForegroundColor Cyan
Write-Host '    [1] Quick     (fast, recommended)'
Write-Host '    [2] Thorough  (also checks DMA via msinfo32, slower)'
Write-Host ''
$scanChoice = Read-Host '  Enter 1 or 2'
$thorough = ($scanChoice -eq '2')
Write-Host ''
 
$dg         = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
$running    = $dg.SecurityServicesRunning
$vbsStatus  = $dg.VirtualizationBasedSecurityStatus
$bcd        = bcdedit /enum '{current}' 2>$null
if ($LASTEXITCODE -ne 0 -or -not $bcd) {
    Write-Host '  WARNING: bcdedit could not be read — boot-config checks (VBS runtime, Hypervisor) may be unreliable.' -ForegroundColor Yellow
}
 
# ----------------------------------------------------------------
# Result store — ordered by dependency (used for root cause logic)
# ----------------------------------------------------------------
$results = [System.Collections.Generic.List[hashtable]]::new()
 
function Add-Result($Name, $Status, $Detail, $Fix) {
    # Status: PASS | FAIL | WARN
    $results.Add(@{ Name = $Name; Status = $Status; Detail = $Detail; Fix = $Fix })
}
 
# ----------------------------------------------------------------
# HELPER — Secure Boot check with reliable fallback
# Confirm-SecureBootUEFI can throw on valid UEFI machines if run
# without full privilege or on certain firmware. We check the
# exception message to distinguish "truly not UEFI" vs other errors.
# ----------------------------------------------------------------
function Get-SecureBootStatus {
    try {
        $val = Confirm-SecureBootUEFI -ErrorAction Stop
        return $val   # $true or $false
    } catch {
        $msg = $_.Exception.Message
        # "Cmdlet not supported on this platform" = genuinely legacy BIOS
        if ($msg -match 'not supported on this platform') { return 'NotSupported' }
        # Any other error (access, WMI glitch) — fall back to WMI property
        # RequiredSecurityProperties: if 2 is present, Secure Boot is required/active
        if ($dg.RequiredSecurityProperties -contains 2) { return $true }
        return 'Unknown'
    }
}
 
# ----------------------------------------------------------------
# HELPER — Kernel DMA Protection via Win32_DeviceGuard (CIM)
# AvailableSecurityProperties value 3 = Kernel DMA Protection is
# available. Unlike Credential Guard, DMA Protection has no separate
# Windows-side on/off switch — if firmware supports it (IOMMU / VT-d /
# AMD-Vi), Windows enables it automatically. So "available" here is
# effectively "on". This reuses the $dg object already queried above,
# so it's instant — no msinfo32 subprocess, no timeout risk.
# ----------------------------------------------------------------
function Get-KernelDMAStatus-Fast {
    if (-not $dg -or $null -eq $dg.AvailableSecurityProperties) {
        return 'QueryFailed'
    }
    if ($dg.AvailableSecurityProperties -contains 3) {
        return 'On'
    }
    return 'NotReported'
}
 
# ----------------------------------------------------------------
# HELPER — Kernel DMA Protection via msinfo32 (thorough mode)
# Reads the literal "Kernel DMA Protection" line msinfo32 reports,
# rather than inferring from hardware capability. Slower — msinfo32
# has to enumerate Loaded Modules, WER history, etc. even though we
# only read one line — so it's bounded with a timeout rather than
# left to run indefinitely.
# ----------------------------------------------------------------
function Get-KernelDMAStatus-Thorough {
    $report = "$env:TEMP\vbs_msinfo_$PID.txt"
    try {
        $proc = Start-Process msinfo32.exe -ArgumentList "/report `"$report`"" -PassThru -ErrorAction Stop
        $exited = $proc.WaitForExit(120000)   # 2 minute cap
 
        if (-not $exited) {
            try { $proc.Kill() } catch {}
            Remove-Item $report -Force -ErrorAction SilentlyContinue
            return 'Timeout'
        }
 
        $line = Select-String -Path $report -Pattern 'Kernel DMA Protection' -ErrorAction SilentlyContinue |
                Select-Object -First 1
        Remove-Item $report -Force -ErrorAction SilentlyContinue
 
        if (-not $line) { return 'NotReported' }
 
        # Split on tabs, filter empty tokens, take last non-empty value
        $parts = ($line.Line -split "`t") | Where-Object { $_.Trim() -ne '' }
        if ($parts.Count -ge 2) { return $parts[-1].Trim() }
 
        # Fall back: split on 2+ spaces, filter empty, take last
        $parts = ($line.Line -split '\s{2,}') | Where-Object { $_.Trim() -ne '' }
        if ($parts.Count -ge 2) { return $parts[-1].Trim() }
 
        return 'ParseError'
    } catch {
        Remove-Item $report -Force -ErrorAction SilentlyContinue
        return 'QueryFailed'
    }
}
 
# ----------------------------------------------------------------
# HELPER — picks fast or thorough DMA check based on scan mode
# ----------------------------------------------------------------
function Get-KernelDMAStatus {
    if ($thorough) {
        return Get-KernelDMAStatus-Thorough
    }
    return Get-KernelDMAStatus-Fast
}
 
# ================================================================
# CHECKS
# ================================================================
 
Write-Host ''
 
# ----------------------------------------------------------------
# VBS  (Secure Boot + DMA prereqs + runtime status, all in one)
# ----------------------------------------------------------------
Write-Host '  VBS' -ForegroundColor Cyan
 
# Secure Boot
$sbStatus = Get-SecureBootStatus
if ($sbStatus -eq $true) {
    Write-Host '    Secure Boot         OK' -ForegroundColor Green
}
elseif ($sbStatus -eq $false) {
    Write-Host '    Secure Boot         DISABLED' -ForegroundColor Red
    Write-Host '    Reason: Secure Boot is off in UEFI firmware' -ForegroundColor DarkGray
    Write-Host '    Fix:    Enable Secure Boot in BIOS/UEFI settings' -ForegroundColor Yellow
    Add-Result 'Secure Boot' 'FAIL' 'Disabled in UEFI firmware' 'Enable Secure Boot in BIOS/UEFI settings'
}
elseif ($sbStatus -eq 'NotSupported') {
    Write-Host '    Secure Boot         NOT SUPPORTED (legacy BIOS)' -ForegroundColor Yellow
    Add-Result 'Secure Boot' 'WARN' 'Platform does not support Secure Boot (legacy BIOS)' ''
}
else {
    Write-Host '    Secure Boot         UNKNOWN (could not query firmware)' -ForegroundColor Yellow
    Add-Result 'Secure Boot' 'WARN' 'Could not read Secure Boot status from firmware' ''
}
 
# Kernel DMA Protection
if ($thorough) {
    Write-Host '    DMA Protection      checking (thorough, via msinfo32)...' -NoNewline -ForegroundColor DarkGray
} else {
    Write-Host '    DMA Protection      checking...' -NoNewline -ForegroundColor DarkGray
}
$dmaStatus = Get-KernelDMAStatus
Write-Host "`r                                                                `r" -NoNewline  # clear "checking..." line
 
if ($dmaStatus -eq 'On') {
    Write-Host '    DMA Protection      OK' -ForegroundColor Green
}
elseif ($dmaStatus -eq 'Off') {
    Write-Host '    DMA Protection      OFF' -ForegroundColor Red
    Write-Host '    Reason: Kernel DMA Protection is disabled' -ForegroundColor DarkGray
    Write-Host '    Fix:    Enable Intel VT-d or AMD-Vi (IOMMU) in BIOS' -ForegroundColor Yellow
    Add-Result 'DMA Protection' 'FAIL' 'Kernel DMA Protection is off' 'Enable Intel VT-d / AMD-Vi (IOMMU) in BIOS — firmware-level setting, not changeable in Windows'
}
elseif ($dmaStatus -eq 'NotReported') {
    if ($thorough) {
        Write-Host '    DMA Protection      NOT SUPPORTED on this platform' -ForegroundColor Yellow
        Write-Host '    Note:   Requires Secured-core PC with IOMMU firmware support' -ForegroundColor DarkGray
        Add-Result 'DMA Protection' 'WARN' 'Platform firmware does not support Kernel DMA Protection' ''
    } else {
        Write-Host '    DMA Protection      UNKNOWN (capability not detected)' -ForegroundColor Yellow
        Write-Host '    Note:   Could mean unsupported hardware, OR that protection is supported but off' -ForegroundColor DarkGray
        Add-Result 'DMA Protection' 'WARN' 'Kernel DMA Protection capability not detected in Quick scan' 'Run the Thorough scan (uses msinfo32) to get a definitive on/off/unsupported result'
    }
}
elseif ($dmaStatus -eq 'Timeout') {
    Write-Host '    DMA Protection      COULD NOT CHECK (msinfo32 timed out)' -ForegroundColor Yellow
    Write-Host '    Reason: msinfo32 took too long to respond (often due to many' -ForegroundColor DarkGray
    Write-Host '            running processes/loaded modules, or WER history)' -ForegroundColor DarkGray
    Write-Host '    Fix:    Close background apps and re-run, or use the quick check' -ForegroundColor Yellow
    Add-Result 'DMA Protection' 'WARN' 'msinfo32 query timed out' 'Close background apps and re-run, or use the quick check'
}
else {
    Write-Host "    DMA Protection      UNKNOWN (query returned: $dmaStatus)" -ForegroundColor Yellow
    Add-Result 'DMA Protection' 'WARN' "Could not determine DMA status ($dmaStatus)" ''
}
 
# VBS runtime
$vsmOff = $bcd | Select-String 'vsmlaunchtype\s+Off'
 
if ($vbsStatus -eq 2 -and -not $vsmOff) {
    Write-Host '    Runtime             OK  (fully active)' -ForegroundColor Green
}
elseif ($vsmOff) {
    Write-Host '    Runtime             DISABLED in boot config' -ForegroundColor Red
    Write-Host '    Reason: vsmlaunchtype is set to Off in BCD' -ForegroundColor DarkGray
    Write-Host '    Fix:    bcdedit /set vsmlaunchtype auto   (run as admin)' -ForegroundColor Yellow
    Add-Result 'VBS' 'FAIL' 'vsmlaunchtype = Off in BCD' 'bcdedit /set vsmlaunchtype auto'
}
else {
    Write-Host "    Runtime             NOT ACTIVE  (status code $vbsStatus)" -ForegroundColor Red
    Write-Host '    Reason: VBS did not reach fully-active state' -ForegroundColor DarkGray
    Write-Host '    Fix:    Ensure Hypervisor is running and Secure Boot is enabled' -ForegroundColor Yellow
    Add-Result 'VBS' 'FAIL' "VBS not fully active (VirtualizationBasedSecurityStatus = $vbsStatus)" 'Ensure Hypervisor is running and prerequisites above are met'
}
 
Write-Host ''
 
# ----------------------------------------------------------------
# HYPERVISOR
# ----------------------------------------------------------------
Write-Host '  Hypervisor' -ForegroundColor Cyan
 
$hyperDetected  = (Get-CimInstance -ClassName Win32_ComputerSystem).HypervisorPresent
$hyperLaunchOff = $bcd | Select-String 'hypervisorlaunchtype\s+Off'
 
if ($hyperLaunchOff) {
    Write-Host '    Status    DISABLED in boot config' -ForegroundColor Red
    Write-Host '    Reason:   hypervisorlaunchtype is set to Off in BCD' -ForegroundColor DarkGray
    Write-Host '    Fix:      bcdedit /set hypervisorlaunchtype auto   (run as admin)' -ForegroundColor Yellow
    Add-Result 'Hypervisor' 'FAIL' 'hypervisorlaunchtype = Off in BCD' 'bcdedit /set hypervisorlaunchtype auto'
}
elseif (-not $hyperDetected) {
    Write-Host '    Status    NOT DETECTED' -ForegroundColor Red
    Write-Host '    Reason:   BIOS virtualization (Intel VT-x / AMD-V) is likely disabled' -ForegroundColor DarkGray
    Write-Host '    Fix:      Enable Intel VT-x or AMD-V in BIOS/UEFI settings' -ForegroundColor Yellow
    Add-Result 'Hypervisor' 'FAIL' 'Hypervisor not running — VT-x/AMD-V likely disabled in BIOS' 'Enable Intel VT-x or AMD-V in BIOS/UEFI settings'
}
else {
    Write-Host '    Status    OK' -ForegroundColor Green
}
 
Write-Host ''
 
# ----------------------------------------------------------------
# CREDENTIAL GUARD
# ----------------------------------------------------------------
Write-Host '  Credential Guard' -ForegroundColor Cyan
 
$lsaPolicy = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' `
            -Name LsaCfgFlags -ErrorAction SilentlyContinue).LsaCfgFlags
$lsaLocal  = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
            -Name LsaCfgFlags -ErrorAction SilentlyContinue).LsaCfgFlags
# Group Policy value takes precedence when configured; otherwise fall back to the local value
$lsa = if ($null -ne $lsaPolicy) { $lsaPolicy } else { $lsaLocal }
$vbsAlreadyFailed = $results | Where-Object { $_.Name -eq 'VBS' -and $_.Status -eq 'FAIL' }
 
if ($running -contains 1 -and $lsa -ne 0) {
    Write-Host '    Status    OK' -ForegroundColor Green
}
elseif ($lsa -eq 0) {
    Write-Host '    Status    NOT ACTIVE' -ForegroundColor Red
    Write-Host '    Reason:   Disabled via registry (LsaCfgFlags = 0)' -ForegroundColor DarkGray
    Write-Host '    Fix:      Set LsaCfgFlags = 1 in HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ForegroundColor Yellow
    Add-Result 'Credential Guard' 'FAIL' 'LsaCfgFlags = 0 in registry' 'Set HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\LsaCfgFlags = 1'
}
elseif ($null -eq $lsa) {
    # No value at all = "not configured", which Windows treats as off — it does
    # NOT mean "enabled, just needs a restart". Deleting the key only clears an
    # explicit disable; it never turns Credential Guard on by itself.
    Write-Host '    Status    NOT ACTIVE' -ForegroundColor Red
    Write-Host '    Reason:   LsaCfgFlags is not set (not configured = off)' -ForegroundColor DarkGray
    Write-Host '    Fix:      Set LsaCfgFlags = 1 in HKLM:\SYSTEM\CurrentControlSet\Control\Lsa, then restart' -ForegroundColor Yellow
    Add-Result 'Credential Guard' 'FAIL' 'LsaCfgFlags not configured' 'Set HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\LsaCfgFlags = 1, then restart your PC'
}
elseif (($running -notcontains 1) -and -not $vbsAlreadyFailed) {
    # LsaCfgFlags is explicitly set to 1 or 2 (enabled) and VBS runtime itself is
    # healthy, but it hasn't launched in this session yet — this is the one case
    # where a restart is actually the correct and sufficient fix.
    Write-Host '    Status    PENDING REBOOT' -ForegroundColor Yellow
    Write-Host '    Reason:   Enabled in registry, but requires a restart to become active' -ForegroundColor DarkGray
    Write-Host '    Fix:      Restart your PC' -ForegroundColor Yellow
    Add-Result 'Credential Guard' 'FAIL' 'Enabled but requires a restart to become active' 'Restart your PC'
}
elseif ($running -notcontains 1) {
    Write-Host '    Status    NOT ACTIVE' -ForegroundColor Red
    Write-Host '    Reason:   Not running inside VBS runtime' -ForegroundColor DarkGray
    Write-Host '    Fix:      Resolve VBS failure first' -ForegroundColor Yellow
    Add-Result 'Credential Guard' 'FAIL' 'Not running in VBS runtime' 'Resolve VBS failure first'
}
else {
    Write-Host '    Status    NOT ACTIVE' -ForegroundColor Red
    Write-Host '    Reason:   Unknown' -ForegroundColor DarkGray
    Add-Result 'Credential Guard' 'FAIL' 'Not active (cause unknown)' ''
}
 
Write-Host ''
 
# ----------------------------------------------------------------
# HVCI
# ----------------------------------------------------------------
Write-Host '  Memory Integrity  (HVCI)' -ForegroundColor Cyan
 
if ($running -contains 2) {
    Write-Host '    Status    OK' -ForegroundColor Green
}
else {
    Write-Host '    Status    DISABLED' -ForegroundColor Red
    Write-Host '    Reason:   HVCI is not running' -ForegroundColor DarkGray
    Write-Host '    Fix:      Check Device Manager for HVCI-incompatible drivers.' -ForegroundColor Yellow
    Write-Host '              Resolve any VBS failure first.' -ForegroundColor Yellow
    Add-Result 'HVCI' 'FAIL' 'Not running — incompatible driver or VBS not active' 'Check Device Manager for flagged drivers. Resolve VBS failure first.'
}
 
Write-Host ''
 
# ================================================================
# ROOT CAUSE SUMMARY
# ================================================================
 
$failures = $results | Where-Object { $_.Status -eq 'FAIL' }
 
if ($failures) {
    $rootCause    = $failures | Select-Object -First 1
    $consequences = $failures | Select-Object -Skip 1
 
    Write-Host '  ═══════════════════════════════' -ForegroundColor DarkGray
    Write-Host '  Root Cause' -ForegroundColor Red
    Write-Host ''
    Write-Host "    $($rootCause.Name)" -ForegroundColor Yellow
    Write-Host "    $($rootCause.Detail)" -ForegroundColor White
    if ($rootCause.Fix -ne '') {
        Write-Host "    Fix: $($rootCause.Fix)" -ForegroundColor Green
    }
 
    if ($consequences) {
        Write-Host ''
        Write-Host '  Likely caused by the above:' -ForegroundColor DarkGray
        $consequences | ForEach-Object {
            Write-Host "    $($_.Name)" -ForegroundColor DarkGray
        }
        Write-Host ''
        Write-Host '  Fix the root cause first — these may resolve on their own.' -ForegroundColor DarkGray
    }
 
    Write-Host ''
}
 
# ================================================================
# OVERALL STATUS
# ================================================================
Write-Host '  ═══════════════════════════════' -ForegroundColor DarkGray
 
$anyFail = $results | Where-Object { $_.Status -eq 'FAIL' }
$anyWarn = $results | Where-Object { $_.Status -eq 'WARN' }
 
if (-not $anyFail -and -not $anyWarn) {
    Write-Host '  Status: ALL CLEAR' -ForegroundColor Green
} elseif (-not $anyFail) {
    Write-Host '  Status: PASS  (with warnings)' -ForegroundColor Yellow
} else {
    Write-Host '  Status: ISSUES FOUND  — see above' -ForegroundColor Red
}
 
Write-Host ''
Read-Host '  Press Enter to close'
 