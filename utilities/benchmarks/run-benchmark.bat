@echo off
rem ======================================================================
rem Avogadro rendering benchmark wrapper for Windows.
rem
rem Runs a standard set of AvogadroRenderBenchmark runs, collects the output
rem in avogadro-benchmark-results.txt (wrapped in a Markdown code fence so
rem it can be pasted straight into https://discuss.avogadro.cc/), copies it
rem to the clipboard and opens it in Notepad.
rem
rem Needs only what ships with Windows 10/11: cmd, PowerShell 5.1, curl.exe.
rem No administrator rights are needed.
rem ======================================================================
setlocal EnableExtensions

rem Work from the folder containing this script (pushd also copes with
rem network paths). Quote every path: folder names may contain spaces.
pushd "%~dp0" || goto :fail_cd
set "HERE=%CD%"
if not "%HERE:~-1%"=="\" set "HERE=%HERE%\"
set "RESULTS=%HERE%avogadro-benchmark-results.txt"
set "JSON_DIR=%HERE%avogadro-benchmark-json"
set "WORK=%TEMP%\avobench-%RANDOM%"
mkdir "%WORK%" >nul 2>&1
set "BODY=%WORK%\body.txt"
set "SYSINFO=%WORK%\sysinfo.txt"
type nul > "%BODY%"

rem --- Locate the benchmark program ---------------------------------------
set "BENCH="
if exist "%HERE%AvogadroRenderBenchmark.exe" set "BENCH=%HERE%AvogadroRenderBenchmark.exe"
if not defined BENCH if exist "%HERE%bin\AvogadroRenderBenchmark.exe" set "BENCH=%HERE%bin\AvogadroRenderBenchmark.exe"
if not defined BENCH goto :fail_nobench

rem --- System information (PowerShell; wmic is gone on Windows 11) --------
rem The header lines go to sysinfo.txt as plain ASCII.
set "AVOSYS=%SYSINFO%"
powershell -NoProfile -ExecutionPolicy Bypass -Command "try { $os=Get-CimInstance Win32_OperatingSystem; $cpu=@(Get-CimInstance Win32_Processor); $cs=Get-CimInstance Win32_ComputerSystem; $gpu=@(Get-CimInstance Win32_VideoController); $c=($cpu | Measure-Object NumberOfCores -Sum).Sum; $t=($cpu | Measure-Object NumberOfLogicalProcessors -Sum).Sum; $l=@(); $l+='Date:   '+(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'); $l+='OS:     '+$os.Caption+' '+$os.Version+' ('+$os.OSArchitecture+')'; $l+='CPU:    '+$cpu[0].Name.Trim()+' ('+$c+' cores / '+$t+' threads)'; $l+='RAM:    about '+[math]::Round($cs.TotalPhysicalMemory/1GB)+' GB'; $l+='Installed GPUs:'; foreach ($g in $gpu) { $l+='  '+$g.Name+' (driver '+$g.DriverVersion+')' }; $l | Set-Content -Encoding ASCII -Path $env:AVOSYS } catch { }" >nul 2>&1

rem Total RAM in MB (0 if unknown).
set "RAM_MB=0"
for /f "usebackq delims=" %%i in (`powershell -NoProfile -Command "[math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory/1MB)"`) do set "RAM_MB=%%i"
rem Guard against non-numeric output.
set /a RAM_MB=%RAM_MB% + 0 >nul 2>&1

rem --- Decide which systems to run ---------------------------------------
set "SKIP_NOTES=%WORK%\skipnotes.txt"
type nul > "%SKIP_NOTES%"
set "HAVE_2MS2=0"
set "HAVE_9MB0=0"

call :fetch 2MS2
if "%FETCH_OK%"=="1" set "HAVE_2MS2=1"
if not "%HAVE_2MS2%"=="1" echo NOTE: 2MS2 skipped - could not download 2MS2.pdb from files.rcsb.org ^(no internet?^)>> "%SKIP_NOTES%"

if %RAM_MB% lss 7000 goto :skip_9mb0
call :fetch 9MB0
if "%FETCH_OK%"=="1" set "HAVE_9MB0=1"
if not "%HAVE_9MB0%"=="1" echo NOTE: 9MB0 skipped - could not download 9MB0.pdb from files.rcsb.org ^(no internet?^)>> "%SKIP_NOTES%"
goto :after_9mb0
:skip_9mb0
if %RAM_MB% equ 0 echo NOTE: 9MB0 skipped - could not determine how much RAM this computer has>> "%SKIP_NOTES%"
if %RAM_MB% gtr 0 echo NOTE: 9MB0 skipped - it needs at least 8 GB of RAM ^(this computer has %RAM_MB% MB^)>> "%SKIP_NOTES%"
:after_9mb0

set /a TOTAL=4
if "%HAVE_2MS2%"=="1" set /a TOTAL+=2
if "%HAVE_9MB0%"=="1" set /a TOTAL+=2

if not exist "%JSON_DIR%" mkdir "%JSON_DIR%"
echo.
echo Avogadro rendering benchmark: %TOTAL% runs.
echo This can take several minutes. Please do not use the computer for
echo anything else until it finishes.
echo.

rem --- Run the benchmarks -------------------------------------------------
set /a N=0
set "RC1="
set "LABEL=10000 water atoms" & set "TAG=water10000" & set "ARGS=--water 10000"
call :runpair
set "LABEL=100000 water atoms" & set "TAG=water100000" & set "ARGS=--water 100000"
call :runpair
if "%HAVE_2MS2%"=="1" set "LABEL=2MS2" & set "TAG=2MS2" & set "ARGS=--file 2MS2.pdb"
if "%HAVE_2MS2%"=="1" call :runpair
if "%HAVE_9MB0%"=="1" set "LABEL=9MB0" & set "TAG=9MB0" & set "ARGS=--file 9MB0.pdb --frames 40"
if "%HAVE_9MB0%"=="1" call :runpair

rem --- Assemble the results file ------------------------------------------
echo Avogadro rendering benchmark results - paste this into the forum thread> "%RESULTS%"
echo ```>> "%RESULTS%"
if exist "%SYSINFO%" type "%SYSINFO%" >> "%RESULTS%"
if not exist "%SYSINFO%" echo ^(system information could not be collected^)>> "%RESULTS%"
echo GPU used by the benchmark (OpenGL):>> "%RESULTS%"
findstr /b /c:"GL_" "%WORK%\run1.txt" >> "%RESULTS%"
if errorlevel 1 echo   ^(not reported - the first run failed^)>> "%RESULTS%"
findstr /i /c:"llvmpipe" "%WORK%\run1.txt" >nul 2>&1
if not errorlevel 1 echo NOTE: software rendering ^(llvmpipe^) was used, so these results measure the CPU only, not a graphics card.>> "%RESULTS%"
type "%SKIP_NOTES%" >> "%RESULTS%"
if "%RC1%"=="0" goto :no_hint
echo HINT: the first run failed. This computer may lack an OpenGL 4 driver>> "%RESULTS%"
echo       ^(common in virtual machines and Remote Desktop sessions^). Updating the>> "%RESULTS%"
echo       graphics driver may help. As a fallback, a Mesa "llvmpipe" opengl32.dll>> "%RESULTS%"
echo       copied next to AvogadroRenderBenchmark.exe gives software rendering;>> "%RESULTS%"
echo       such results are CPU-only and should be labelled as software rendering.>> "%RESULTS%"
:no_hint
echo.>> "%RESULTS%"
type "%BODY%" >> "%RESULTS%"
echo ```>> "%RESULTS%"

rem --- Clipboard and Notepad ---------------------------------------------
rem Everything in the file is plain ASCII, so clip.exe keeps it intact.
clip < "%RESULTS%"
start "" notepad "%RESULTS%"

echo.
echo Done. Results saved to:
echo   %RESULTS%
echo Results copied to the clipboard and opened in Notepad.
echo Paste them into a reply at https://discuss.avogadro.cc/
echo.
rd /s /q "%WORK%" >nul 2>&1
popd
pause
exit /b 0

rem ======================================================================
rem Subroutines
rem ======================================================================

rem :runpair - run the current LABEL/TAG/ARGS in rebuild then render mode.
:runpair
for %%M in (rebuild render) do call :one %%M
exit /b 0

rem :one MODE - a single benchmark run; appends its output to the body.
:one
set /a N+=1
echo Running %N% of %TOTAL%: %LABEL%, %1 ...
"%BENCH%" %ARGS% --mode %1 --json "%JSON_DIR%\%TAG%_%1.json" > "%WORK%\run%N%.txt" 2>&1
set "RC=%ERRORLEVEL%"
if %N% equ 1 set "RC1=%RC%"
echo === %LABEL%, %1 mode ===>> "%BODY%"
if "%RC%"=="0" type "%WORK%\run%N%.txt" >> "%BODY%"
if not "%RC%"=="0" call :failed_run
echo.>> "%BODY%"
exit /b 0

rem :failed_run - record the exit code and the tail of the output.
:failed_run
echo RUN FAILED with exit code %RC%. Last 20 lines of output:>> "%BODY%"
set "AVOFILE=%WORK%\run%N%.txt"
powershell -NoProfile -Command "if (Test-Path -LiteralPath $env:AVOFILE) { Get-Content -Tail 20 -LiteralPath $env:AVOFILE }" >> "%BODY%" 2>&1
exit /b 0

rem :fetch ID - make sure ID.pdb exists here and is not empty; sets FETCH_OK.
:fetch
set "FETCH_OK=0"
if exist "%~1.pdb" call :checksize "%~1.pdb"
if "%FETCH_OK%"=="1" exit /b 0
echo Downloading %~1.pdb ...
set "URL=https://files.rcsb.org/download/%~1.pdb"
where curl.exe >nul 2>&1
if not errorlevel 1 curl.exe -fsSL -o "%~1.pdb" "%URL%" >nul 2>&1
if exist "%~1.pdb" call :checksize "%~1.pdb"
if "%FETCH_OK%"=="1" exit /b 0
rem Fallback for systems without curl.exe: PowerShell 5.1 needs TLS 1.2.
set "AVOURL=%URL%"
set "AVOOUT=%HERE%%~1.pdb"
powershell -NoProfile -ExecutionPolicy Bypass -Command "try { [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -UseBasicParsing -Uri $env:AVOURL -OutFile $env:AVOOUT } catch { }" >nul 2>&1
if exist "%~1.pdb" call :checksize "%~1.pdb"
if "%FETCH_OK%"=="1" exit /b 0
if exist "%~1.pdb" del "%~1.pdb" >nul 2>&1
exit /b 0

rem :checksize FILE - sets FETCH_OK=1 if FILE is larger than 0 bytes.
:checksize
if %~z1 gtr 0 set "FETCH_OK=1"
exit /b 0

rem ======================================================================
rem Error exits
rem ======================================================================
:fail_cd
echo Could not switch to the folder containing this script.
pause
exit /b 1

:fail_nobench
echo.
echo Could not find AvogadroRenderBenchmark.exe.
echo Put this script in the same folder as AvogadroRenderBenchmark.exe
echo ^(or next to a "bin" folder that contains it^), then run it again.
echo If you opened it from inside a ZIP file, extract the ZIP first.
echo.
popd
pause
exit /b 1
