@echo off
chcp 65001 >nul
cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
  echo [오류] 파이썬이 없습니다. python.org 에서 설치하고 "Add Python to PATH" 를 체크하세요.
  pause
  exit /b 1
)

echo [1/3] 필요한 패키지 설치 중...
python -m pip install --upgrade pyinstaller==6.11.1 yara-python pystray pillow || goto :fail

echo [2/3] MaeGuard.exe 만드는 중...
python -m PyInstaller --noconfirm --clean --onefile --windowed ^
  --name MaeGuard ^
  --hidden-import yara ^
  --hidden-import pystray._win32 ^
  --icon icon.ico ^
  --add-data "signatures.txt;." ^
  --add-data "icon.ico;." ^
  --add-data "assets\mark_small.png;assets" ^
  maeguard_gui.py || goto :fail
copy /y signatures.txt dist\ >nul

echo [3/3] 설치 프로그램 만드는 중...
set "NSIS="
where makensis >nul 2>nul && set "NSIS=makensis"
if not defined NSIS if exist "%ProgramFiles(x86)%\NSIS\makensis.exe" set "NSIS=%ProgramFiles(x86)%\NSIS\makensis.exe"
if not defined NSIS if exist "%ProgramFiles%\NSIS\makensis.exe" set "NSIS=%ProgramFiles%\NSIS\makensis.exe"
if not defined NSIS (
  echo NSIS 설치 중...
  winget install --id NSIS.NSIS -e --silent --accept-package-agreements --accept-source-agreements
  if exist "%ProgramFiles(x86)%\NSIS\makensis.exe" set "NSIS=%ProgramFiles(x86)%\NSIS\makensis.exe"
)
if not defined NSIS (
  echo.
  echo [안내] NSIS 를 찾지 못해 설치 프로그램은 건너뜁니다. exe 는 정상적으로 만들어졌습니다.
  echo        https://nsis.sourceforge.io 에서 NSIS 를 설치한 뒤 build.bat 을 다시 실행하세요.
  goto :done
)
"%NSIS%" /V2 installer.nsi || goto :fail

:done
echo.
echo 완료!
echo   dist\MaeGuard.exe              - 프로그램 단독 실행 파일
echo   dist\MaeGuard_Setup_1.4.0.exe  - 배포용 설치 프로그램
explorer dist
pause
exit /b 0

:fail
echo 빌드 실패
pause
exit /b 1
