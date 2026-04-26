setlocal EnableDelayedExpansion

:: --- Colour codes (Windows 10+) ---
set GREEN=[92m
set RED=[91m
set YELLOW=[93m
set CYAN=[96m
set RESET=[0m

echo.
echo %CYAN%+================================================================+%RESET%
echo %CYAN%^|   RansomWall File System Minifilter Driver Installer          ^|%RESET%
echo %CYAN%+================================================================+%RESET%
echo.

:: --- Administrator check ---
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo %RED%[ERROR] This script must be run as Administrator.%RESET%
    echo         Right-click install_driver.bat -^> "Run as administrator"
    pause
    exit /b 1
)
echo %GREEN%[OK]%RESET%    Running as Administrator.

:: --- OS check ---
ver | find "Windows" >nul
if %errorlevel% neq 0 (
    echo %RED%[ERROR] This driver requires Windows OS.%RESET%
    exit /b 1
)
echo %GREEN%[OK]%RESET%    Windows OS detected.

:: --- Parse argument ---
set ACTION=install
if /i "%~1"=="uninstall" set ACTION=uninstall
if /i "%~1"=="testsign"  set ACTION=testsign
if /i "%~1"=="status"    set ACTION=status
if /i "%~1"=="build"     set ACTION=build

if "%ACTION%"=="testsign" (
    echo.
    echo %YELLOW%[INFO] Enabling Test Signing Mode...%RESET%
    echo        This allows loading unsigned/test-signed drivers.
    echo        A REBOOT is required after this step.
    echo.

    bcdedit /set testsigning on
    if !errorlevel! neq 0 (
        echo %RED%[ERROR] Failed to enable test signing. Check Secure Boot settings.%RESET%
        echo         If Secure Boot is enabled, disable it in UEFI/BIOS first.
        pause
        exit /b 1
    )

    echo %GREEN%[OK]%RESET%    Test signing enabled.
    echo.
    echo %YELLOW%[ACTION REQUIRED]%RESET%
    echo   1. Create a test certificate:
    echo      makecert -r -pe -ss TestCertStore -n "CN=RansomWall Test" RansomWall.cer
    echo   2. Sign the driver:
    echo      signtool sign /v /fd sha256 /s TestCertStore /n "RansomWall Test" RansomWallFilter.sys
    echo   3. REBOOT the system.
    echo   4. Run this script again without 'testsign' to install.
    echo.
    pause
    exit /b 0
)


if "%ACTION%"=="build" (
    echo.
    echo %YELLOW%[INFO] Building RansomWallFilter.sys...%RESET%

    set MSBUILD=
    for %%p in (
        "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin\MSBuild.exe"
        "C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\MSBuild\15.0\Bin\MSBuild.exe"
        "C:\Program Files (x86)\MSBuild\14.0\Bin\MSBuild.exe"
    ) do (
        if exist %%p set MSBUILD=%%p
    )

    if not defined MSBUILD (
        echo %RED%[ERROR] MSBuild not found. Install Visual Studio with WDK support.%RESET%
        echo         WDK download: https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk
        exit /b 1
    )

    if not exist "RansomWallFilter.vcxproj" (
        echo %RED%[ERROR] RansomWallFilter.vcxproj not found in current directory.%RESET%
        exit /b 1
    )

    echo %CYAN%[BUILD]%RESET% Running MSBuild...
    %MSBUILD% RansomWallFilter.vcxproj /p:Configuration=Release /p:Platform=x64 /nologo /verbosity:minimal
    if !errorlevel! neq 0 (
        echo %RED%[ERROR] Build failed. Check the output above for errors.%RESET%
        exit /b 1
    )

    echo %GREEN%[OK]%RESET%    Build successful.
    echo        Output: x64\Release\RansomWallFilter.sys
    echo.
    echo %YELLOW%[NEXT]%RESET% Sign the driver, then run: install_driver.bat install
    pause
    exit /b 0
)

if "%ACTION%"=="status" (
    echo.
    echo %CYAN%[STATUS] Checking RansomWallFilter driver status...%RESET%
    echo.

    sc query RansomWallFilter >nul 2>&1
    if !errorlevel! neq 0 (
        echo %YELLOW%  Driver status: NOT INSTALLED%RESET%
    ) else (
        sc query RansomWallFilter
    )

    echo.
    echo %CYAN%[STATUS] Test signing mode:%RESET%
    bcdedit /enum | find "testsigning"

    echo.
    echo %CYAN%[STATUS] Loaded minifilter drivers:%RESET%
    fltmc
    exit /b 0
)

:: ===========================================================================
:: UNINSTALL
:: ===========================================================================
if "%ACTION%"=="uninstall" (
    echo.
    echo %YELLOW%[INFO] Uninstalling RansomWallFilter...%RESET%

    :: Stop the driver first
    echo %CYAN%[STEP 1/3]%RESET% Stopping driver service...
    fltmc unload RansomWallFilter >nul 2>&1
    sc stop RansomWallFilter >nul 2>&1
    timeout /t 2 /nobreak >nul

    :: Unregister via sc
    echo %CYAN%[STEP 2/3]%RESET% Removing service entry...
    sc delete RansomWallFilter >nul 2>&1

    :: Remove registry keys
    echo %CYAN%[STEP 3/3]%RESET% Cleaning registry...
    reg delete "HKLM\SYSTEM\CurrentControlSet\Services\RansomWallFilter" /f >nul 2>&1

    echo.
    echo %GREEN%[DONE]%RESET%   RansomWallFilter uninstalled.
    echo        The .sys file has NOT been deleted from System32\drivers.
    echo        Delete manually if needed:
    echo        del /f "%SystemRoot%\System32\drivers\RansomWallFilter.sys"
    pause
    exit /b 0
)

echo.

:: --- Check for the .sys file ---
set SYS_FILE=
if exist "RansomWallFilter.sys"              set SYS_FILE=RansomWallFilter.sys
if exist "x64\Release\RansomWallFilter.sys"  set SYS_FILE=x64\Release\RansomWallFilter.sys
if exist "Release\RansomWallFilter.sys"      set SYS_FILE=Release\RansomWallFilter.sys

if not defined SYS_FILE (
    echo %RED%[ERROR] RansomWallFilter.sys not found.%RESET%
    echo.
    echo        Build the driver first:
    echo          install_driver.bat build
    echo.
    echo        Expected locations:
    echo          .\RansomWallFilter.sys
    echo          .\x64\Release\RansomWallFilter.sys
    pause
    exit /b 1
)
echo %GREEN%[OK]%RESET%    Found driver: %SYS_FILE%

:: --- Check for .inf file ---
if not exist "RansomWallFilter.inf" (
    echo %RED%[ERROR] RansomWallFilter.inf not found in current directory.%RESET%
    pause
    exit /b 1
)
echo %GREEN%[OK]%RESET%    Found INF:    RansomWallFilter.inf

:: --- Check test signing status ---
bcdedit /enum | find "testsigning" | find "Yes" >nul 2>&1
if !errorlevel! neq 0 (
    echo %YELLOW%[WARN]%RESET%   Test signing is NOT enabled.
    echo         The driver may fail to load if it has no production EV certificate.
    echo         To enable test mode: install_driver.bat testsign  (then reboot)
    echo.
)

:: --- Stop existing instance ---
echo %CYAN%[STEP 1/5]%RESET% Stopping existing driver (if any)...
fltmc unload RansomWallFilter >nul 2>&1
sc stop RansomWallFilter >nul 2>&1
timeout /t 1 /nobreak >nul

:: --- Copy .sys to drivers directory ---
echo %CYAN%[STEP 2/5]%RESET% Copying driver to System32\drivers...
copy /y "%SYS_FILE%" "%SystemRoot%\System32\drivers\RansomWallFilter.sys" >nul
if !errorlevel! neq 0 (
    echo %RED%[ERROR] Failed to copy driver file. Check permissions.%RESET%
    pause
    exit /b 1
)
echo %GREEN%[OK]%RESET%    Copied to %SystemRoot%\System32\drivers\RansomWallFilter.sys

:: --- Register via sc create ---
echo %CYAN%[STEP 3/5]%RESET% Registering driver service...
sc query RansomWallFilter >nul 2>&1
if !errorlevel! equ 0 (
    echo        Service already exists. Updating...
    sc delete RansomWallFilter >nul 2>&1
    timeout /t 1 /nobreak >nul
)

sc create RansomWallFilter ^
    type= filesys ^
    binPath= "%SystemRoot%\System32\drivers\RansomWallFilter.sys" ^
    start= demand ^
    DisplayName= "RansomWall File System Filter Driver"

if !errorlevel! neq 0 (
    echo %RED%[ERROR] sc create failed.%RESET%
    pause
    exit /b 1
)

:: --- Set filter altitude registry key ---
echo %CYAN%[STEP 4/5]%RESET% Setting minifilter altitude (370030)...
reg add "HKLM\SYSTEM\CurrentControlSet\Services\RansomWallFilter\Parameters" ^
    /v "SupportedFeatures" /t REG_DWORD /d 3 /f >nul

reg add "HKLM\SYSTEM\CurrentControlSet\Services\RansomWallFilter\Parameters\Instances" ^
    /v "DefaultInstance" /t REG_SZ /d "RansomWall Instance" /f >nul

reg add "HKLM\SYSTEM\CurrentControlSet\Services\RansomWallFilter\Parameters\Instances\RansomWall Instance" ^
    /v "Altitude" /t REG_SZ /d "370030" /f >nul

reg add "HKLM\SYSTEM\CurrentControlSet\Services\RansomWallFilter\Parameters\Instances\RansomWall Instance" ^
    /v "Flags" /t REG_DWORD /d 0 /f >nul

echo %GREEN%[OK]%RESET%    Registry configured.

:: --- Start the driver ---
echo %CYAN%[STEP 5/5]%RESET% Starting RansomWallFilter...
sc start RansomWallFilter
if !errorlevel! neq 0 (
    echo.
    echo %RED%[ERROR] Failed to start driver.%RESET%
    echo.
    echo        Common causes:
    echo          1. Driver not signed: run 'install_driver.bat testsign' then reboot
    echo          2. Secure Boot blocking unsigned drivers: disable in UEFI
    echo          3. Driver build error: rebuild with WDK
    echo.
    echo        Check Windows Event Log:
    echo          eventvwr.msc -> Windows Logs -> System
    echo          Look for Source: "Service Control Manager" or "RansomWallFilter"
    echo.
    sc delete RansomWallFilter >nul 2>&1
    pause
    exit /b 1
)

timeout /t 2 /nobreak >nul

:: --- Verify with fltmc ---
echo.
echo %CYAN%[VERIFY] Loaded minifilter drivers:%RESET%
fltmc | find "RansomWall"
if !errorlevel! neq 0 (
    echo %YELLOW%[WARN]%RESET%   RansomWallFilter not in fltmc output.
    echo         Check Event Log for load errors.
) else (
    echo %GREEN%[OK]%RESET%    RansomWallFilter loaded and active!
)

echo.
echo %GREEN%+================================================================+%RESET%
echo %GREEN%^|   RansomWallFilter.sys INSTALLED SUCCESSFULLY                 ^|%RESET%
echo %GREEN%^|                                                                ^|%RESET%
echo %GREEN%^|   Now run:  python main.py --kernel                           ^|%RESET%
echo %GREEN%^|        OR:  python kernel_main.py                             ^|%RESET%
echo %GREEN%+================================================================+%RESET%
echo.
echo        Kernel port: \RansomWallPort
echo        Altitude:    370030  (FSFilter Activity Monitor group)
echo        IRP types:   READ, WRITE, SET_INFORMATION, DIRECTORY_CONTROL
echo.
echo        To uninstall: install_driver.bat uninstall
echo        To check:     install_driver.bat status
echo.

pause
exit /b 0
