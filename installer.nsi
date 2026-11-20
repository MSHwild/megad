Unicode true
SetCompressor /SOLID lzma

!ifndef VERSION
  !define VERSION "1.4.1"
!endif
!define APPNAME "매가드"
!define EXE "MaeGuard.exe"
!define UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\MaeGuard"
!define RUN_KEY "Software\Microsoft\Windows\CurrentVersion\Run"

Name "${APPNAME}"
OutFile "dist\MaeGuard_Setup_${VERSION}.exe"
RequestExecutionLevel user
InstallDir "$LOCALAPPDATA\Programs\MaeGuard"
InstallDirRegKey HKCU "${UNINST_KEY}" "InstallLocation"
BrandingText "${APPNAME} ${VERSION}"

VIProductVersion "${VERSION}.0"
VIAddVersionKey /LANG=1042 "ProductName" "${APPNAME}"
VIAddVersionKey /LANG=1042 "FileDescription" "${APPNAME} 설치 프로그램"
VIAddVersionKey /LANG=1042 "FileVersion" "${VERSION}"
VIAddVersionKey /LANG=1042 "ProductVersion" "${VERSION}"
VIAddVersionKey /LANG=1042 "LegalCopyright" "MaeGuard"

!include "MUI2.nsh"
!define MUI_ICON "icon.ico"
!define MUI_UNICON "icon.ico"
!define MUI_WELCOMEFINISHPAGE_BITMAP "assets\installer_welcome.bmp"
!define MUI_UNWELCOMEFINISHPAGE_BITMAP "assets\installer_welcome.bmp"
!define MUI_ABORTWARNING
!define MUI_WELCOMEPAGE_TITLE "${APPNAME} 설치"
!define MUI_WELCOMEPAGE_TEXT "${APPNAME}는 다운로드 · 바탕화면 · 문서 폴더를 실시간으로 감시해서$\r$\n의심스러운 파일을 찾아 차단할지 물어봅니다.$\r$\n$\r$\nWindows Defender와 함께 사용하세요.$\r$\n$\r$\n[다음]을 눌러 계속하세요."
!define MUI_COMPONENTSPAGE_NODESC
!define MUI_FINISHPAGE_RUN "$INSTDIR\${EXE}"
!define MUI_FINISHPAGE_RUN_TEXT "${APPNAME} 실행하기"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "Korean"

!macro CloseApp
  nsExec::Exec 'taskkill /F /IM ${EXE}'
  Pop $0
  Sleep 800
!macroend

Section "${APPNAME} (필수)" SecMain
  SectionIn RO
  !insertmacro CloseApp
  SetOutPath "$INSTDIR"
  File "dist\${EXE}"
  File "signatures.txt"
  File "icon.ico"
  WriteUninstaller "$INSTDIR\uninstall.exe"

  CreateDirectory "$SMPROGRAMS\${APPNAME}"
  CreateShortcut "$SMPROGRAMS\${APPNAME}\${APPNAME}.lnk" "$INSTDIR\${EXE}" "" "$INSTDIR\icon.ico"
  CreateShortcut "$SMPROGRAMS\${APPNAME}\${APPNAME} 제거.lnk" "$INSTDIR\uninstall.exe"

  WriteRegStr HKCU "${UNINST_KEY}" "DisplayName" "${APPNAME}"
  WriteRegStr HKCU "${UNINST_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKCU "${UNINST_KEY}" "Publisher" "MaeGuard"
  WriteRegStr HKCU "${UNINST_KEY}" "DisplayIcon" "$INSTDIR\icon.ico"
  WriteRegStr HKCU "${UNINST_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "${UNINST_KEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKCU "${UNINST_KEY}" "QuietUninstallString" '"$INSTDIR\uninstall.exe" /S'
  WriteRegDWORD HKCU "${UNINST_KEY}" "NoModify" 1
  WriteRegDWORD HKCU "${UNINST_KEY}" "NoRepair" 1
  WriteRegDWORD HKCU "${UNINST_KEY}" "EstimatedSize" 30000
SectionEnd

Section "바탕화면 바로가기" SecDesktop
  CreateShortcut "$DESKTOP\${APPNAME}.lnk" "$INSTDIR\${EXE}" "" "$INSTDIR\icon.ico"
SectionEnd

Section "윈도우 시작 시 자동 실행 (권장)" SecAutostart
  WriteRegStr HKCU "${RUN_KEY}" "MaeGuard" '"$INSTDIR\${EXE}" --tray'
SectionEnd

Section "Uninstall"
  !insertmacro CloseApp
  DeleteRegValue HKCU "${RUN_KEY}" "MaeGuard"
  Delete "$INSTDIR\${EXE}"
  Delete "$INSTDIR\signatures.txt"
  Delete "$INSTDIR\icon.ico"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"
  Delete "$DESKTOP\${APPNAME}.lnk"
  Delete "$SMPROGRAMS\${APPNAME}\${APPNAME}.lnk"
  Delete "$SMPROGRAMS\${APPNAME}\${APPNAME} 제거.lnk"
  RMDir "$SMPROGRAMS\${APPNAME}"
  DeleteRegKey HKCU "${UNINST_KEY}"

  IfSilent keep_data
  MessageBox MB_YESNO|MB_ICONQUESTION "격리된 파일, 검사 기록, 설정도 모두 삭제할까요?$\r$\n(아니요를 누르면 다시 설치할 때 그대로 사용합니다)" IDNO keep_data
    RMDir /r "$PROFILE\.maeguard"
  keep_data:
SectionEnd
