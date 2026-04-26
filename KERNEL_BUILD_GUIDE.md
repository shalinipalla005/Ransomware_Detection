# RansomWall Kernel Implementation Guide
## Paper §IV-B / §IV-D — COMSNETS 2018 | Shaukat & Ribeiro, IIT Delhi

---

## What was added (kernel-level completion)

| File | Purpose |
|---|---|
| `RansomWallFilter.c` | Kernel minifilter driver — IRP interception, entropy, fingerprint, port |
| `RansomWallFilter.inf` | Driver installation descriptor (altitude, instance, service) |
| `RansomWallFilter.vcxproj` | Visual Studio / WDK build project |
| `kernel_bridge.py` | User-mode ↔ kernel bridge (FilterConnectCommunicationPort / FilterGetMessage) |
| `kernel_main.py` ★ NEW | Full pipeline orchestrator using the kernel driver |
| `install_driver.bat` ★ NEW | One-click driver installation script (batch) |
| `install_driver.ps1` ★ NEW | Full PowerShell installer with signing, building, status |

---

## Architecture (paper §IV-A / §IV-B)

```
[User File I/O]
      │
[Windows I/O Manager]
      │
[Filter Manager] ←── RansomWallFilter.sys  ◄── THIS IS THE KERNEL LAYER
      │
      │  FltSendMessage → named port \RansomWallPort
      │
[kernel_bridge.py]            ◄── user-mode bridge (Python)
      │
      ├── DynamicEngine.inject_irp()     (READ/WRITE/RENAME/DELETE/DIR_QUERY)
      ├── TrapLayer.inject_test_event()  (honey file events from kernel path)
      └── FeatureCollector → MLModel (GBT, 3-bucket sliding window)
              │
              ├── Ransomware → kernel_bridge.kill_pid()   [ZwTerminateProcess]
              └── Benign     → kernel_bridge.whitelist_pid() + backup.cleanup()
```

### Why kernel-level matters (paper §IV-B)

The paper explicitly requires a **minifilter driver** because:
- Watchdog-based monitoring (inotify / ReadDirectoryChangesW) has race conditions
- Ransomware can rename/delete files faster than user-mode observers can react
- A kernel filter driver intercepts IRPs **before** they reach the file system
- Process kill via `ZwTerminateProcess` in kernel mode cannot be blocked by the ransomware

---

## IRP Operations Intercepted

| IRP Major Function | Callback | Paper Feature |
|---|---|---|
| `IRP_MJ_READ` | `RansomWallPreRead` | §III-D-3b: File Read Operations |
| `IRP_MJ_WRITE` (pre) | `RansomWallPreWrite` | §III-D-3c: File Write Operations |
| `IRP_MJ_WRITE` (post) | `RansomWallPostWrite` | §III-D-3g: Shannon Entropy of File Writes |
| `IRP_MJ_SET_INFORMATION` rename | `RansomWallPreSetInfo` | §III-D-3d: Data-to-NonData Rename |
| `IRP_MJ_SET_INFORMATION` delete | `RansomWallPreSetInfo` | §III-D-3e: File Delete Operations |
| `IRP_MJ_DIRECTORY_CONTROL` | `RansomWallPreDirCtrl` | §III-D-3a: Directory Info Queries |

Fingerprint mismatch (§III-D-3f) is checked in `RansomWallPostWrite` using `FltReadFile` to compare magic bytes against file extension.

---

## Build Requirements (paper §IV-D)

```
- Microsoft Visual Studio 2015 or later (2019/2022 recommended)
- Microsoft Windows Driver Kit (WDK) 10
- Windows SDK 10
- Target: Windows 7 / 8.1 / 10 / 11 (x64)
```

### Download links
- WDK: https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk
- SDK: https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/

---

## Step-by-Step Setup

### Step 1 — Build the driver

```powershell
# From WDK x64 Native Tools Command Prompt (or Developer PowerShell):
.\install_driver.ps1 -Action build

# Or directly:
msbuild RansomWallFilter.vcxproj /p:Configuration=Release /p:Platform=x64
# Output: x64\Release\RansomWallFilter.sys
```

### Step 2 — Enable Test Signing (first-time setup, requires reboot)

> Skip this if you have a production EV code-signing certificate.

```powershell
# Run PowerShell as Administrator:
.\install_driver.ps1 -Action testsign

# This will:
# 1. Run: bcdedit /set testsigning on
# 2. Create a self-signed certificate in Cert:\LocalMachine\My
# 3. Add it to Root + TrustedPublisher stores
# 4. Sign RansomWallFilter.sys with SHA-256

# --- REBOOT after this step ---
Restart-Computer
```

Or using the batch file:
```bat
install_driver.bat testsign
:: Follow the on-screen instructions, then reboot
```

### Step 3 — Install the driver

```powershell
# PowerShell (run as Administrator):
.\install_driver.ps1 -Action install

# Or batch (run as Administrator):
install_driver.bat
```

This will:
1. Copy `RansomWallFilter.sys` → `%SystemRoot%\System32\drivers\`
2. Register it as a file system service via `sc create`
3. Configure altitude `370030` in the registry (`FSFilter Activity Monitor` group)
4. Start the driver via `sc start`
5. Verify it appears in `fltmc` output

### Step 4 — Run the Python pipeline

```bash
# With kernel driver (Windows, Admin not required for Python):
python kernel_main.py --demo
python kernel_main.py --monitor
python kernel_main.py --static suspect.exe --monitor

# Check driver stats:
python kernel_main.py --stats

# Or use the original main.py (auto-detects kernel driver):
python main.py --demo
```

### Step 5 — Verify

```bat
install_driver.bat status

:: Should show:
::   RansomWallFilter   370030   ...   (Instances: 1)
::   Driver status: Running
::   Communication port: OPEN
```

---

## Communication Protocol

### Kernel → Python (IRP events)

The kernel driver calls `FltSendMessage` to send `RANSOMWALL_IRP_MESSAGE` structs.
The Python bridge calls `FilterGetMessage` in a blocking loop and parses each message.

```
struct RANSOMWALL_IRP_MESSAGE {
  MessageSize       : 4 bytes  (sizeof struct)
  Version           : 4 bytes  (= 1)
  ProcessId         : 4 bytes
  ThreadId          : 4 bytes
  ProcessName[260]  : 520 bytes (WCHAR, image name)
  Operation         : 4 bytes  (RANSOMWALL_OP_TYPE enum)
  Timestamp         : 8 bytes  (LARGE_INTEGER)
  FileSize          : 4 bytes
  FilePath[520]     : 1040 bytes (WCHAR, full NT path)
  FileExtension[16] : 32 bytes
  DestPath[520]     : 1040 bytes (rename destination)
  DestExtension[16] : 32 bytes
  EntropyX100       : 4 bytes  (Shannon entropy × 100)
  IsTargetExtension : 1 byte   (BOOLEAN)
  IsRansomExtension : 1 byte   (BOOLEAN)
  FingerprintMismatch:1 byte   (BOOLEAN)
}
Total: ~1704 bytes
```

### Python → Kernel (control commands)

```python
bridge.kill_pid(pid)       # → RW_CMD_KILL_PID      → ZwTerminateProcess
bridge.whitelist_pid(pid)  # → RW_CMD_WHITELIST_PID → no more IRPs for this PID
bridge.get_driver_stats()  # → RW_CMD_STATUS        → (total, suspicious, dropped)
```

---

## Whitelist / Suspension Logic

When the ML Engine classifies a PID as **benign**, `kernel_bridge.whitelist_pid(pid)` 
sends `RW_CMD_WHITELIST_PID` to the kernel. The driver adds the PID to 
`g_WhitelistPids[]` and `RwBuildAndSendMessage()` returns immediately for all 
subsequent IRPs from that PID — eliminating false-positive overhead.

---

## Driver Altitude

`370030` is in the `FSFilter Activity Monitor` group (Altitudes 320000–329999 are 
reserved; 370000–389999 are for activity monitors). This means RansomWallFilter 
sits above AV/backup filters but below content filters, consistent with the paper's 
detection role.

---

## Uninstall

```powershell
.\install_driver.ps1 -Action uninstall
# Or:
install_driver.bat uninstall
```

To disable test signing after uninstall:
```bat
bcdedit /set testsigning off
:: Then reboot
```

---

## Troubleshooting

| Error | Cause | Fix |
|---|---|---|
| `sc start` fails with 577 | Driver not signed | Run testsign step, reboot |
| `sc start` fails with 5 | Secure Boot blocking | Disable Secure Boot in UEFI |
| Python: `fltlib.dll not available` | Not on Windows | Windows-only feature |
| Python: `HRESULT=0x80070005` | Not Admin / no access | Run Python as Admin |
| Driver loads but no IRPs | Altitude conflict | Check `fltmc` for conflicts |
| `FilterGetMessage` timeout | No file I/O | Perform file operations to trigger |

---

## Paper vs Implementation Mapping

| Paper Section | Implementation |
|---|---|
| §III-B-3 Dynamic Analysis Engine | `RansomWallFilter.c` IRP callbacks + `ransomwall_dynamic_layer.py` |
| §III-D-3a Directory Info Queries | `RansomWallPreDirCtrl` → `inject_irp("dir_query")` |
| §III-D-3b File Read Operations | `RansomWallPreRead` → `inject_irp("read")` |
| §III-D-3c File Write Operations | `RansomWallPreWrite` + `PostWrite` → `inject_irp("write")` |
| §III-D-3d Data-to-NonData Rename | `RansomWallPreSetInfo` FileRenameInformation → `inject_irp("rename")` |
| §III-D-3e File Delete Operations | `RansomWallPreSetInfo` FileDispositionInformation → `inject_irp("delete")` |
| §III-D-3f File Fingerprinting | `RwCheckFingerprintMismatch` via `FltReadFile` in `PostWrite` |
| §III-D-3g Shannon Entropy | `RwComputeEntropyX100` on MDL write buffer in `PostWrite` |
| §IV-A IRP Filter Port | `FltCreateCommunicationPort` + `FilterConnectCommunicationPort` |
| §IV-B Minifilter Driver | `FltRegisterFilter` + `FLT_REGISTRATION g_FilterRegistration` |
| §III-B-4 Kill Process | `ZwTerminateProcess` via `RW_CMD_KILL_PID` in `RansomWallMessageNotify` |
| §III-B-4 Whitelist Benign | `g_WhitelistPids[]` via `RW_CMD_WHITELIST_PID` |
| §V-G System Overhead | `< 1% CPU` for normal: achieved by 0-timeout FltSendMessage (drop if busy) |
