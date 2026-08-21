@echo off
setlocal EnableExtensions
chcp 65001 >nul

set "WSL=C:\Windows\System32\wsl.exe"
set "REPO_WIN=E:\ckb_workspace\ReZygisk"
set "REPO_WSL=/mnt/e/ckb_workspace/ReZygisk"
set "NDK_WSL=/mnt/e/ckb_workspace/.codex-tools/android-ndk-r29-beta1-linux/android-ndk-r29-beta1"

echo ============================================================
echo Building IRezygisk i27 Release
echo Source: %REPO_WIN%
echo ============================================================

if not exist "%WSL%" (
  echo [ERROR] WSL not found: %WSL%
  goto :failed
)

if not exist "%REPO_WIN%\Makefile" (
  echo [ERROR] ReZygisk source not found: %REPO_WIN%
  goto :failed
)

if not exist "E:\ckb_workspace\.codex-tools\android-ndk-r29-beta1-linux\android-ndk-r29-beta1\source.properties" (
  echo [ERROR] Android NDK r29 beta1 not found.
  goto :failed
)

"%WSL%" -e bash --noprofile --norc -c "set -euo pipefail; cd '%REPO_WSL%'; make clean; make release NDK_PATH='%NDK_WSL%'"
if errorlevel 1 goto :failed

echo.
echo [OK] Release build completed.
powershell.exe -NoLogo -NoProfile -Command ^
  "$z=Get-ChildItem -LiteralPath '%REPO_WIN%\build\out' -Filter 'IRezygisk-v1.0.0-i27-564-*-release.zip' | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1; if(-not $z){throw 'Release ZIP was not found'}; Write-Host ('ZIP:    '+$z.FullName); Write-Host ('Size:   '+$z.Length+' bytes'); Write-Host ('SHA256: '+(Get-FileHash -LiteralPath $z.FullName -Algorithm SHA256).Hash)"
if errorlevel 1 goto :failed

echo.
pause
exit /b 0

:failed
echo.
echo [ERROR] Build failed. Review the messages above.
pause
exit /b 1
