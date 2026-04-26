<#
.SYNOPSIS
    RansomWall Kernel Driver - Full Installation and Management Script

.DESCRIPTION
    Complete PowerShell installer for RansomWallFilter.sys.
    Handles: build verification, test-signing, installation, service
    registration, fltmc loading, and uninstallation.

.PARAMETER Action
    install   - Install and start the driver (default)
    uninstall - Stop and remove the driver
    testsign  - Create self-signed test cert and sign the driver
    build     - Invoke MSBuild to compile the driver
    status    - Show current driver status
    sign      - Sign an existing .sys with existing cert

.PARAMETER SysPath
    Path to RansomWallFilter.sys (auto-detected if omitted)

.PARAMETER CertName
    Certificate CN for signing (default: "RansomWall Test")

.EXAMPLE
    .\install_driver.ps1 -Action testsign
    .\install_driver.ps1 -Action install
    .\install_driver.ps1 -Action status
    .\install_driver.ps1 -Action uninstall
#>

[CmdletBinding()]
param(
    [ValidateSet("install","uninstall","testsign","build","status","sign")]
    [string]$Action = "install",
    [string]$SysPath = "",
    [string]$CertName = "RansomWall Test",
    [string]$CertStore = "TestCertStore"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Constants ─────────────────────────────────────────────────────────────────
$DRIVER_NAME    = "RansomWallFilter"
$SERVICE_DISPLAY= "RansomWall File System Filter Driver"
$ALTITUDE       = "370030"
$PORT_NAME      = "\RansomWallPort"
$DRVSYS_DEST    = "$env:SystemRoot\System32\drivers\$DRIVER_NAME.sys"

# ── Helpers ───────────────────────────────────────────────────────────────────
function Write-Banner {
    Write-Host ""
    Write-Host "+================================================================+" -ForegroundColor Cyan
    Write-Host "|   RansomWall File System Minifilter Driver Installer           |" -ForegroundColor Cyan
    Write-Host "+================================================================+" -ForegroundColor Cyan
    Write-Host ""
}

function Test-Administrator {
    $currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Find-DriverSys {
    $candidates = @(
        ".\RansomWallFilter.sys",
        ".\x64\Release\RansomWallFilter.sys",
        ".\Release\RansomWallFilter.sys",
        ".\bin\x64\Release\RansomWallFilter.sys"
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) { return (Resolve-Path $c).Path }
    }
    return $null
}

function Find-MSBuild {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $vsPath = & $vswhere -latest -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe 2>$null | Select-Object -First 1
        if ($vsPath -and (Test-Path $vsPath)) { return $vsPath }
    }
    # Fallback search
    $fallbacks = @(
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe",
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin\MSBuild.exe",
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2017\Community\MSBuild\15.0\Bin\MSBuild.exe",
        "${env:ProgramFiles(x86)}\MSBuild\14.0\Bin\MSBuild.exe"
    )
    foreach ($fb in $fallbacks) {
        if (Test-Path $fb) { return $fb }
    }
    return $null
}

function Find-SignTool {
    $candidates = @(
        "C:\Program Files (x86)\Windows Kits\10\bin\x64\signtool.exe",
        "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe",
        "C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x64\signtool.exe"
    )
    # Also check via where.exe
    try { $w = where.exe signtool 2>$null; if ($w) { return $w } } catch {}
    foreach ($c in $candidates) {
        if (Test-Path $c) { return $c }
    }
    return $null
}

function Find-MakeCert {
    $candidates = @(
        "C:\Program Files (x86)\Windows Kits\10\bin\x64\makecert.exe",
        "C:\Program Files (x86)\Windows Kits\10\bin\x86\makecert.exe"
    )
    foreach ($c in $candidates) { if (Test-Path $c) { return $c } }
    return $null
}

function Set-RegistryKey {
    param([string]$Path, [string]$Name, $Value, [string]$Type = "String")
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type
}

function Stop-DriverIfRunning {
    try {
        $svc = Get-Service -Name $DRIVER_NAME -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -ne "Stopped") {
            Write-Host "  Stopping existing driver service..." -ForegroundColor Yellow
            & fltmc unload $DRIVER_NAME 2>$null
            Stop-Service -Name $DRIVER_NAME -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
        }
    } catch {}
}

# ══════════════════════════════════════════════════════════════════════════════
# ACTION: STATUS
# ══════════════════════════════════════════════════════════════════════════════
function Invoke-Status {
    Write-Host "[STATUS] RansomWallFilter Driver Status" -ForegroundColor Cyan
    Write-Host ""

    $svc = Get-Service -Name $DRIVER_NAME -ErrorAction SilentlyContinue
    if ($svc) {
        Write-Host "  Service name   : $($svc.Name)"
        Write-Host "  Display name   : $($svc.DisplayName)"
        Write-Host "  Status         : $($svc.Status)" -ForegroundColor $(if ($svc.Status -eq "Running") {"Green"} else {"Yellow"})
        Write-Host "  Start type     : $($svc.StartType)"
    } else {
        Write-Host "  Service status : NOT INSTALLED" -ForegroundColor Red
    }

    Write-Host ""
    Write-Host "[STATUS] Test Signing Mode:" -ForegroundColor Cyan
    $tsResult = & bcdedit /enum 2>$null | Select-String "testsigning"
    if ($tsResult) { Write-Host "  $tsResult" } else { Write-Host "  (not set / Off)" }

    Write-Host ""
    Write-Host "[STATUS] Loaded Minifilter Drivers (fltmc):" -ForegroundColor Cyan
    & fltmc 2>$null | Where-Object { $_ -match "RansomWall" -or $_ -match "Filter Name" -or $_ -match "-----" }

    Write-Host ""
    Write-Host "[STATUS] Driver file:" -ForegroundColor Cyan
    if (Test-Path $DRVSYS_DEST) {
        $fi = Get-Item $DRVSYS_DEST
        Write-Host "  Found : $DRVSYS_DEST"
        Write-Host "  Size  : $($fi.Length) bytes"
        Write-Host "  Date  : $($fi.LastWriteTime)"
    } else {
        Write-Host "  NOT FOUND at $DRVSYS_DEST" -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "[STATUS] Communication port ($PORT_NAME):" -ForegroundColor Cyan
    $portTest = python -c "
import ctypes, sys
try:
    lib = ctypes.WinDLL('fltlib.dll')
    h = ctypes.c_void_p()
    hr = lib.FilterConnectCommunicationPort('\\\\RansomWallPort', 0, None, 0, None, ctypes.byref(h))
    if hr == 0:
        lib.FilterPortClose(h)
        print('OPEN - driver is accepting connections')
    else:
        print(f'CLOSED (hr=0x{hr & 0xFFFFFFFF:08X})')
except Exception as e:
    print(f'ERROR: {e}')
" 2>$null
    Write-Host "  $portTest"
}

# ══════════════════════════════════════════════════════════════════════════════
# ACTION: TESTSIGN - create cert and sign the driver
# ══════════════════════════════════════════════════════════════════════════════
function Invoke-TestSign {
    Write-Host "[TEST-SIGN] Setting up test signing for RansomWallFilter..." -ForegroundColor Yellow
    Write-Host ""

    # Find signtool
    $signtool = Find-SignTool
    if (-not $signtool) {
        Write-Error "signtool.exe not found. Install Windows SDK 10."
        return
    }
    Write-Host "  signtool : $signtool" -ForegroundColor Green

    # Find makecert (optional: for legacy cert creation)
    $makecert = Find-MakeCert

    # Locate the driver
    $sysFile = if ($SysPath) { $SysPath } else { Find-DriverSys }
    if (-not $sysFile -or -not (Test-Path $sysFile)) {
        Write-Error "RansomWallFilter.sys not found. Build it first: .\install_driver.ps1 -Action build"
        return
    }
    Write-Host "  sys file : $sysFile" -ForegroundColor Green

    # Step 1: Enable test signing in BCD
    Write-Host ""
    Write-Host "[STEP 1/4] Enabling bcdedit test signing..." -ForegroundColor Cyan
    $bcResult = & bcdedit /set testsigning on 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "bcdedit failed: $bcResult"
        Write-Warning "If Secure Boot is enabled, disable it in UEFI/BIOS first."
    } else {
        Write-Host "  [OK] Test signing enabled. Reboot required before driver can load." -ForegroundColor Green
    }

    # Step 2: Create a self-signed certificate using New-SelfSignedCertificate (PowerShell 5+)
    Write-Host ""
    Write-Host "[STEP 2/4] Creating self-signed code signing certificate..." -ForegroundColor Cyan
    Write-Host "  CN       : $CertName"
    Write-Host "  Store    : Cert:\LocalMachine\My  +  Cert:\LocalMachine\Root"

    try {
        # Check if cert already exists
        $existingCert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -like "*$CertName*" } | Select-Object -First 1
        if ($existingCert) {
            Write-Host "  Certificate already exists: $($existingCert.Thumbprint)" -ForegroundColor Yellow
            $cert = $existingCert
        } else {
            $cert = New-SelfSignedCertificate `
                -Subject "CN=$CertName" `
                -Type CodeSigningCert `
                -CertStoreLocation Cert:\LocalMachine\My `
                -KeyUsage DigitalSignature `
                -HashAlgorithm SHA256 `
                -KeyLength 2048 `
                -NotAfter (Get-Date).AddYears(5) `
                -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3")

            Write-Host "  [OK] Certificate created: $($cert.Thumbprint)" -ForegroundColor Green
        }

        # Export cert and add to Root store (so it's trusted)
        $certFile = "RansomWall_TestCert.cer"
        Export-Certificate -Cert $cert -FilePath $certFile | Out-Null
        Import-Certificate -FilePath $certFile -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
        Import-Certificate -FilePath $certFile -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null
        Write-Host "  [OK] Certificate added to Root and TrustedPublisher stores." -ForegroundColor Green

    } catch {
        Write-Warning "Certificate creation failed: $_"
        Write-Warning "Trying legacy makecert approach..."
        if ($makecert) {
            & $makecert -r -pe -ss $CertStore -n "CN=$CertName" -eku 1.3.6.1.5.5.7.3.3 "$certFile" 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Error "makecert also failed. Install Windows SDK."
                return
            }
        } else {
            Write-Error "Neither New-SelfSignedCertificate nor makecert succeeded."
            return
        }
    }

    # Step 3: Sign the .sys file
    Write-Host ""
    Write-Host "[STEP 3/4] Signing $sysFile..." -ForegroundColor Cyan
    $signArgs = @(
        "sign",
        "/v",
        "/fd", "sha256",
        "/s", "My",
        "/n", $CertName,
        "/t", "http://timestamp.digicert.com",
        $sysFile
    )
    try {
        & $signtool @signArgs
        if ($LASTEXITCODE -ne 0) {
            # Retry without timestamp (in case network is unavailable)
            Write-Warning "Timestamp server unavailable. Signing without timestamp..."
            $signArgs = @("sign","/v","/fd","sha256","/s","My","/n",$CertName,$sysFile)
            & $signtool @signArgs
        }
        if ($LASTEXITCODE -ne 0) {
            Write-Error "signtool failed."
            return
        }
        Write-Host "  [OK] Driver signed successfully." -ForegroundColor Green
    } catch {
        Write-Error "Signing failed: $_"
        return
    }

    # Step 4: Verify signature
    Write-Host ""
    Write-Host "[STEP 4/4] Verifying signature..." -ForegroundColor Cyan
    & $signtool verify /pa $sysFile 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  [OK] Signature verified." -ForegroundColor Green
    } else {
        Write-Warning "Signature verification returned non-zero. This may be OK for test signing."
    }

    Write-Host ""
    Write-Host "[DONE] Test signing complete." -ForegroundColor Green
    Write-Host ""
    Write-Host "  IMPORTANT: You must REBOOT before loading the driver, then run:" -ForegroundColor Yellow
    Write-Host "    .\install_driver.ps1 -Action install" -ForegroundColor Yellow
    Write-Host ""
}

# ══════════════════════════════════════════════════════════════════════════════
# ACTION: BUILD
# ══════════════════════════════════════════════════════════════════════════════
function Invoke-Build {
    Write-Host "[BUILD] Compiling RansomWallFilter.sys..." -ForegroundColor Cyan
    Write-Host ""

    if (-not (Test-Path "RansomWallFilter.vcxproj")) {
        Write-Error "RansomWallFilter.vcxproj not found in current directory."
        return
    }

    $msbuild = Find-MSBuild
    if (-not $msbuild) {
        Write-Error "MSBuild not found. Install Visual Studio 2017+ with WDK integration."
        Write-Host ""
        Write-Host "  Download WDK: https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk"
        return
    }
    Write-Host "  MSBuild: $msbuild" -ForegroundColor Green

    Write-Host ""
    Write-Host "  Building Release|x64 configuration..." -ForegroundColor Cyan
    & $msbuild "RansomWallFilter.vcxproj" `
        /p:Configuration=Release `
        /p:Platform=x64 `
        /nologo `
        /verbosity:minimal

    if ($LASTEXITCODE -ne 0) {
        Write-Error "Build failed. Review the output above."
        return
    }

    $outputSys = Find-DriverSys
    if ($outputSys) {
        Write-Host ""
        Write-Host "  [OK] Build successful: $outputSys" -ForegroundColor Green
        $fi = Get-Item $outputSys
        Write-Host "       Size: $($fi.Length) bytes"
    } else {
        Write-Warning "Build reported success but .sys not found."
    }
}

# ══════════════════════════════════════════════════════════════════════════════
# ACTION: UNINSTALL
# ══════════════════════════════════════════════════════════════════════════════
function Invoke-Uninstall {
    Write-Host "[UNINSTALL] Removing RansomWallFilter..." -ForegroundColor Yellow
    Write-Host ""

    Write-Host "[STEP 1/3] Unloading from Filter Manager..."
    & fltmc unload $DRIVER_NAME 2>$null
    Write-Host "[STEP 2/3] Stopping service..."
    Stop-Service -Name $DRIVER_NAME -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    Write-Host "[STEP 3/3] Deleting service entry..."
    & sc.exe delete $DRIVER_NAME 2>$null

    # Registry cleanup
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$DRIVER_NAME"
    if (Test-Path $regPath) {
        Remove-Item -Path $regPath -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "  Registry key removed."
    }

    Write-Host ""
    Write-Host "[DONE] $DRIVER_NAME uninstalled." -ForegroundColor Green
    Write-Host "  The .sys file was NOT deleted from System32\drivers."
    Write-Host "  Remove manually if needed: del $DRVSYS_DEST"
}

# ══════════════════════════════════════════════════════════════════════════════
# ACTION: INSTALL  (main installation path)
# ══════════════════════════════════════════════════════════════════════════════
function Invoke-Install {
    Write-Host "[INSTALL] Installing RansomWallFilter..." -ForegroundColor Cyan
    Write-Host ""

    # Locate .sys
    $sysFile = if ($SysPath -and (Test-Path $SysPath)) { $SysPath } else { Find-DriverSys }
    if (-not $sysFile) {
        Write-Error "RansomWallFilter.sys not found. Run: .\install_driver.ps1 -Action build"
        return
    }
    Write-Host "  [OK] Found: $sysFile" -ForegroundColor Green

    # Verify signature
    $signtool = Find-SignTool
    if ($signtool) {
        Write-Host "  Verifying driver signature..."
        $verResult = & $signtool verify /pa $sysFile 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Driver is not signed or signature is invalid."
            Write-Warning "Load may fail on Windows 10/11. Run: .\install_driver.ps1 -Action testsign"
        } else {
            Write-Host "  [OK] Driver signature valid." -ForegroundColor Green
        }
    }

    # Stop existing
    Stop-DriverIfRunning

    # STEP 1: Copy .sys to drivers dir
    Write-Host ""
    Write-Host "[STEP 1/5] Copying to $DRVSYS_DEST..."
    Copy-Item -Path $sysFile -Destination $DRVSYS_DEST -Force
    Write-Host "  [OK] Copied." -ForegroundColor Green

    # STEP 2: Delete old service entry
    Write-Host "[STEP 2/5] Removing old service entry (if any)..."
    & sc.exe delete $DRIVER_NAME 2>$null
    Start-Sleep -Milliseconds 500

    # STEP 3: Create service
    Write-Host "[STEP 3/5] Creating service entry..."
    & sc.exe create $DRIVER_NAME `
        type= filesys `
        binPath= $DRVSYS_DEST `
        start= demand `
        DisplayName= $SERVICE_DISPLAY

    if ($LASTEXITCODE -ne 0) {
        Write-Error "sc.exe create failed."
        return
    }
    Write-Host "  [OK] Service created." -ForegroundColor Green

    # STEP 4: Configure registry (altitude + instance)
    Write-Host "[STEP 4/5] Configuring minifilter altitude ($ALTITUDE)..."
    $baseKey  = "HKLM:\SYSTEM\CurrentControlSet\Services\$DRIVER_NAME"
    $paramKey = "$baseKey\Parameters"
    $instKey  = "$paramKey\Instances"
    $instName = "RansomWall Instance"
    $inst1Key  = "$instKey\$instName"

    Set-RegistryKey $paramKey "SupportedFeatures" 3 "DWord"
    Set-RegistryKey $instKey  "DefaultInstance"    $instName "String"
    Set-RegistryKey $inst1Key "Altitude"            $ALTITUDE "String"
    Set-RegistryKey $inst1Key "Flags"               0 "DWord"
    Write-Host "  [OK] Registry configured." -ForegroundColor Green

    # STEP 5: Start the driver
    Write-Host "[STEP 5/5] Starting $DRIVER_NAME..."
    & sc.exe start $DRIVER_NAME
    if ($LASTEXITCODE -ne 0) {
        Write-Host ""
        Write-Error "Failed to start driver (exit code $LASTEXITCODE)."
        Write-Host ""
        Write-Host "Troubleshooting:" -ForegroundColor Yellow
        Write-Host "  1. Enable test signing: .\install_driver.ps1 -Action testsign"
        Write-Host "     Then REBOOT, then run install again."
        Write-Host "  2. Check Event Log: eventvwr.msc -> System"
        Write-Host "  3. If Secure Boot is on: disable in UEFI/BIOS"
        Write-Host "  4. Verify driver with: signtool verify /pa $DRVSYS_DEST"
        & sc.exe delete $DRIVER_NAME 2>$null
        return
    }

    Start-Sleep -Seconds 2

    # Verify via fltmc
    Write-Host ""
    Write-Host "[VERIFY] Checking fltmc..." -ForegroundColor Cyan
    $fltOutput = & fltmc 2>&1
    $rwLine    = $fltOutput | Where-Object { $_ -match "RansomWall" }

    if ($rwLine) {
        Write-Host ""
        Write-Host "+================================================================+" -ForegroundColor Green
        Write-Host "|   RansomWallFilter.sys LOADED SUCCESSFULLY                     |" -ForegroundColor Green
        Write-Host "|                                                                 |" -ForegroundColor Green
        Write-Host "|   $rwLine" -ForegroundColor Green
        Write-Host "|                                                                 |" -ForegroundColor Green
        Write-Host "|   Run: python kernel_main.py  OR  python main.py --kernel      |" -ForegroundColor Green
        Write-Host "+================================================================+" -ForegroundColor Green
    } else {
        Write-Warning "RansomWallFilter not visible in fltmc output."
        Write-Warning "Driver may have loaded but not registered with Filter Manager."
        Write-Host "Full fltmc output:" -ForegroundColor Yellow
        $fltOutput | Write-Host
    }

    Write-Host ""
    Write-Host "  Kernel port   : $PORT_NAME"
    Write-Host "  Altitude      : $ALTITUDE  (FSFilter Activity Monitor)"
    Write-Host "  IRP callbacks : READ, WRITE, SET_INFORMATION, DIRECTORY_CONTROL"
    Write-Host ""
    Write-Host "  Uninstall: .\install_driver.ps1 -Action uninstall"
    Write-Host "  Status   : .\install_driver.ps1 -Action status"
    Write-Host ""
}

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

Write-Banner

# Administrator check
if (-not (Test-Administrator)) {
    Write-Host "[ERROR] Must run as Administrator." -ForegroundColor Red
    Write-Host "  Right-click PowerShell -> 'Run as Administrator'"
    Write-Host "  Then: Set-ExecutionPolicy Bypass -Scope Process"
    exit 1
}
Write-Host "  [OK] Running as Administrator." -ForegroundColor Green
Write-Host "  [OK] Action: $Action" -ForegroundColor Green
Write-Host ""

switch ($Action) {
    "install"   { Invoke-Install }
    "uninstall" { Invoke-Uninstall }
    "testsign"  { Invoke-TestSign }
    "build"     { Invoke-Build }
    "status"    { Invoke-Status }
    "sign"      {
        $sysFile = if ($SysPath) { $SysPath } else { Find-DriverSys }
        if (-not $sysFile) { Write-Error "No .sys file found."; exit 1 }
        $Action = "testsign"
        Invoke-TestSign
    }
}
