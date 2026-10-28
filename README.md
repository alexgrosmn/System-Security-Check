# System Security Check

A PowerShell tool that audits the Windows virtualization-based security (VBS) stack and tells you not just *what* is off, but *why*.

Windows features like Credential Guard and Memory Integrity depend on a chain of prerequisites: firmware settings, the hypervisor, and VBS itself. When one link breaks, everything after it fails too, and Windows Security usually just reports "off" with no explanation. System Security Check walks the whole chain, reports the status of each layer, and points you to the first failure so you know what to fix first.

## What it checks

| Component | What it looks at |
|---|---|
| Secure Boot | `Confirm-SecureBootUEFI`, with a Device Guard fallback |
| Kernel DMA Protection | Device Guard security properties (Quick scan) or the `msinfo32` report (Thorough scan) |
| VBS runtime | `Win32_DeviceGuard` status and `vsmlaunchtype` in the boot configuration |
| Hypervisor | `HypervisorPresent` and `hypervisorlaunchtype` in the boot configuration |
| Credential Guard | Running security services and the `LsaCfgFlags` registry value (Group Policy and local) |
| Memory Integrity (HVCI) | Running security services |

## Features

- **Root-cause summary.** The first failure in the chain is reported as the root cause, and the failures after it are listed as likely side effects.
- **Specific fixes.** Every failure comes with a reason and a suggested fix: a BIOS setting, a `bcdedit` command, or a registry value.
- **Two scan modes.**
  - *Quick* reads everything from WMI and finishes in seconds.
  - *Thorough* also runs `msinfo32` for a definitive Kernel DMA Protection result (capped at 2 minutes).
- **Read-only.** The script never changes your system. Fixes are printed for you to apply yourself, and the only file it writes is a temporary `msinfo32` report that it deletes afterwards.
- **Color-coded output** with an overall status: `ALL CLEAR`, `PASS (with warnings)`, or `ISSUES FOUND`.

## Requirements

- Windows 10 or 11
- Windows PowerShell 5.1 (included with Windows)
- Administrator privileges

## Usage

1. Download the repo: click **Code → Download ZIP** and extract it, or run:
   ```bash
   git clone https://github.com/alexgrosmn/System-Security-Check.git
   ```
2. Right-click `ssc.bat` and choose **Run as administrator**.
3. Enter `1` for a Quick scan or `2` for a Thorough scan.

To run the script directly instead, open PowerShell as administrator in the project folder and run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ".\System Security Check.ps1"
```

`-ExecutionPolicy Bypass` applies only to that one PowerShell process. It doesn't change your system's execution policy.

## Example output

A machine with Secure Boot turned off in firmware:

```
  VBS
    Secure Boot         DISABLED
    Reason: Secure Boot is off in UEFI firmware
    Fix:    Enable Secure Boot in BIOS/UEFI settings
    DMA Protection      OK
    Runtime             NOT ACTIVE  (status code 0)
    Reason: VBS did not reach fully-active state
    Fix:    Ensure Hypervisor is running and Secure Boot is enabled

  Hypervisor
    Status    OK

  ...

  ═══════════════════════════════
  Root Cause

    Secure Boot
    Disabled in UEFI firmware
    Fix: Enable Secure Boot in BIOS/UEFI settings

  Likely caused by the above:
    VBS
    Credential Guard
    HVCI

  Fix the root cause first — these may resolve on their own.

  ═══════════════════════════════
  Status: ISSUES FOUND  — see above
```

## Limitations

- **Credential Guard needs Windows Enterprise or Education.** It isn't supported on Home or Pro, so on those editions it will always show as not active.
- **Quick-scan DMA results are inferred** from hardware capability. Run a Thorough scan for a definitive answer.
- **Thorough mode expects English Windows.** It searches the `msinfo32` report for the English label "Kernel DMA Protection".

## Project structure

```
System-Security-Check/
├── ssc.bat                      # Launcher: runs the PowerShell script
├── System Security Check.ps1    # The checker
└── README.md
```

## Disclaimer

The suggested fixes change firmware, boot, or registry settings. Read up on each one before applying it, and note that incompatible drivers can block Memory Integrity from turning on.

## Author

[alexgrosmn](https://github.com/alexgrosmn)
