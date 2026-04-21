<#
.SYNOPSIS
    Resets Windows Update components on Windows 10/11 to recover from
    corrupted WU state (e.g. 0x800706f4, 0x80070002, 0x8024xxxx errors).

.DESCRIPTION
    Modern rewrite of Ryan Nemeth's classic Reset-WUEng.ps1, updated for
    Windows 10/11. Performs the standard WU component reset:

      - Stops WU-related services
      - Clears BITS queue manager data
      - Renames SoftwareDistribution and catroot2
      - Re-registers the DLLs that still matter on modern Windows
      - Resets WinSock and WinHTTP proxy
      - Flushes BITS jobs
      - Clears any stale WSUS client identifiers
      - Restarts services and kicks off a scan via the modern USO/COM API
      - Optionally runs DISM + SFC for component store repair

    Requires an elevated PowerShell session. Writes a transcript to
    C:\Tools\Logs\ for audit purposes.

.PARAMETER SkipRepair
    Skip the DISM /RestoreHealth and sfc /scannow passes at the end.
    These are slow (10-30 min) but usually worth running.

.PARAMETER LogPath
    Directory for the transcript. Defaults to C:\Tools\Logs.

.EXAMPLE
    .\Reset-WindowsUpdate.ps1

.EXAMPLE
    .\Reset-WindowsUpdate.ps1 -SkipRepair

.NOTES
    Author:  Fractional IT
    Based on prior art by Ryan Nemeth (geekyryan.com)
    Tested:  Windows 10 22H2, Windows 11 23H2/24H2
#>

#Requires -RunAsAdministrator
#Requires -Version 5.1

[CmdletBinding()]
param(
    [switch]$SkipRepair,
    [string]$LogPath = 'C:\Tools\Logs'
)

$ErrorActionPreference = 'Continue'

# --- Transcript setup -------------------------------------------------------
if (-not (Test-Path $LogPath)) {
    New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
}
$transcript = Join-Path $LogPath ("Reset-WindowsUpdate_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
Start-Transcript -Path $transcript -Force | Out-Null

function Write-Step {
    param([string]$Message)
    Write-Host "`n==> $Message" -ForegroundColor Cyan
}

try {
    Write-Host "Reset-WindowsUpdate starting on $env:COMPUTERNAME at $(Get-Date)" -ForegroundColor Green
    Write-Host "OS: $((Get-CimInstance Win32_OperatingSystem).Caption) $((Get-CimInstance Win32_OperatingSystem).Version)"

    # --- 1. Stop services ---------------------------------------------------
    Write-Step "Stopping Windows Update services"
    $services = @('wuauserv', 'bits', 'cryptsvc', 'appidsvc', 'msiserver', 'usosvc')
    foreach ($svc in $services) {
        $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($s) {
            if ($s.Status -ne 'Stopped') {
                Write-Host "  Stopping $svc..."
                Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
            } else {
                Write-Host "  $svc already stopped"
            }
        }
    }

    # Give services a moment to fully release file handles
    Start-Sleep -Seconds 3

    # --- 2. Remove BITS queue manager data ---------------------------------
    Write-Step "Clearing BITS queue manager data"
    $qmgrPath = Join-Path $env:ProgramData 'Microsoft\Network\Downloader'
    if (Test-Path $qmgrPath) {
        Get-ChildItem -Path $qmgrPath -Filter 'qmgr*.dat' -ErrorAction SilentlyContinue |
            Remove-Item -Force -ErrorAction SilentlyContinue
    }

    # --- 3. Rename SoftwareDistribution and catroot2 -----------------------
    Write-Step "Renaming SoftwareDistribution and catroot2"
    $timestamp = Get-Date -Format 'yyyyMMddHHmmss'
    $sdPath    = Join-Path $env:SystemRoot 'SoftwareDistribution'
    $crPath    = Join-Path $env:SystemRoot 'System32\catroot2'

    foreach ($item in @($sdPath, $crPath)) {
        if (Test-Path $item) {
            $newName = "$(Split-Path $item -Leaf).bak_$timestamp"
            try {
                Rename-Item -Path $item -NewName $newName -ErrorAction Stop
                Write-Host "  Renamed $item -> $newName"
            } catch {
                Write-Warning "  Could not rename $item : $_"
            }
        }
    }

    # --- 4. Remove legacy WindowsUpdate.log --------------------------------
    Write-Step "Removing legacy WindowsUpdate.log (if present)"
    Remove-Item "$env:SystemRoot\WindowsUpdate.log" -Force -ErrorAction SilentlyContinue

    # --- 5. Re-register DLLs relevant on Windows 10/11 ---------------------
    Write-Step "Re-registering Windows Update DLLs"
    Push-Location "$env:SystemRoot\System32"

    # Trimmed to DLLs that still exist and matter on modern Windows.
    # Dropped from Ryan's original: wuaueng1.dll, wucltui.dll, wuweb.dll,
    # muweb.dll (removed in Win10), gpkcsp, sccbase, slbcsp, cryptdlg
    # (legacy CAPI1), msxml.dll (v2 - gone).
    $dlls = @(
        'atl.dll', 'urlmon.dll', 'mshtml.dll', 'shdocvw.dll', 'browseui.dll',
        'jscript.dll', 'vbscript.dll', 'scrrun.dll', 'msxml3.dll', 'msxml6.dll',
        'actxprxy.dll', 'softpub.dll', 'wintrust.dll', 'dssenh.dll', 'rsaenh.dll',
        'oleaut32.dll', 'ole32.dll', 'shell32.dll', 'initpki.dll',
        'wuapi.dll', 'wuaueng.dll', 'wups.dll', 'wups2.dll',
        'qmgr.dll', 'qmgrprxy.dll', 'wucltux.dll', 'wuwebv.dll'
    )

    $failed = @()
    foreach ($dll in $dlls) {
        if (Test-Path $dll) {
            $p = Start-Process -FilePath 'regsvr32.exe' -ArgumentList '/s', $dll `
                -Wait -PassThru -WindowStyle Hidden
            if ($p.ExitCode -ne 0) { $failed += "$dll (exit $($p.ExitCode))" }
        }
    }
    Pop-Location
    if ($failed.Count) {
        Write-Warning "  DLLs that failed to register: $($failed -join ', ')"
    } else {
        Write-Host "  All DLLs registered cleanly"
    }

    # --- 6. Remove stale WSUS client identifiers ---------------------------
    Write-Step "Clearing stale WSUS client identifiers (if present)"
    $wuKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate'
    foreach ($value in 'AccountDomainSid', 'PingID', 'SusClientId', 'SusClientIdValidation') {
        if (Get-ItemProperty -Path $wuKey -Name $value -ErrorAction SilentlyContinue) {
            Remove-ItemProperty -Path $wuKey -Name $value -Force -ErrorAction SilentlyContinue
            Write-Host "  Removed $value"
        }
    }

    # --- 7. Reset network stacks -------------------------------------------
    Write-Step "Resetting WinSock and WinHTTP proxy"
    Write-Host "  (WinSock reset requires a reboot to fully take effect)"
    & netsh winsock reset | Out-Null
    & netsh winhttp reset proxy | Out-Null

    # --- 8. Flush BITS jobs ------------------------------------------------
    Write-Step "Flushing BITS jobs (all users)"
    try {
        Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue |
            Remove-BitsTransfer -ErrorAction SilentlyContinue
    } catch {
        Write-Warning "  BITS job cleanup: $_"
    }

    # --- 9. Start services -------------------------------------------------
    Write-Step "Starting Windows Update services"
    # Start in dependency order
    foreach ($svc in 'cryptsvc', 'bits', 'wuauserv', 'appidsvc', 'usosvc') {
        $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($s) {
            try {
                Start-Service -Name $svc -ErrorAction Stop
                Write-Host "  Started $svc"
            } catch {
                Write-Warning "  Could not start $svc : $_"
            }
        }
    }

    # --- 10. Trigger a scan (modern API) -----------------------------------
    Write-Step "Triggering update detection"
    # UsoClient is the Windows 10/11 replacement for wuauclt /detectnow.
    # The COM call is more reliable than the CLI wrapper.
    try {
        $auto = New-Object -ComObject 'Microsoft.Update.AutoUpdate'
        $auto.DetectNow()
        Write-Host "  DetectNow() invoked via Microsoft.Update.AutoUpdate"
    } catch {
        Write-Warning "  COM detect failed, falling back to UsoClient: $_"
        & "$env:SystemRoot\System32\UsoClient.exe" StartScan 2>&1 | Out-Null
    }

    # --- 11. Optional: component store repair ------------------------------
    if (-not $SkipRepair) {
        Write-Step "Running DISM /RestoreHealth (this can take 10-30 minutes)"
        & dism.exe /Online /Cleanup-Image /RestoreHealth
        Write-Host "  DISM exit code: $LASTEXITCODE"

        Write-Step "Running sfc /scannow"
        & sfc.exe /scannow
        Write-Host "  SFC exit code: $LASTEXITCODE"
    } else {
        Write-Host "`nSkipping DISM + SFC (SkipRepair specified)" -ForegroundColor Yellow
    }

    Write-Host "`n============================================================" -ForegroundColor Green
    Write-Host " Reset complete. A reboot is strongly recommended before"     -ForegroundColor Green
    Write-Host " retrying Windows Update."                                    -ForegroundColor Green
    Write-Host " Transcript: $transcript"                                     -ForegroundColor Green
    Write-Host "============================================================" -ForegroundColor Green
}
catch {
    Write-Error "Unhandled error: $_"
    throw
}
finally {
    Stop-Transcript | Out-Null
}
