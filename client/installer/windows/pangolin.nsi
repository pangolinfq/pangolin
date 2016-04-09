Name "Pangolin 代理"

OutFile "pangolin-__VERSION__-install.exe"

InstallDir $DESKTOP\Pangolin

RequestExecutionLevel user

;--------------------------------

; Pages
Page components
Page directory
Page instfiles

UninstPage uninstConfirm
UninstPage instfiles

;--------------------------------
; install
Section "Pangolin 代理"

  SectionIn RO
 
  SetOutPath $INSTDIR
  
  File pangolin.exe
  
  WriteUninstaller "uninstall.exe"
  
SectionEnd

; Optional section (can be disabled by the user)
Section "开始菜单"

  CreateDirectory "$SMPROGRAMS\Pangolin"
  CreateShortcut "$SMPROGRAMS\Pangolin\Uninstall.lnk" "$INSTDIR\uninstall.exe" "" "$INSTDIR\uninstall.exe" 0
  CreateShortcut "$SMPROGRAMS\Pangolin\Pangolin 代理.lnk" "$INSTDIR\pangolin.exe"
  
SectionEnd

Section "快捷方式"

  CreateShortcut "$DESKTOP\Pangolin 代理.lnk" "$INSTDIR\pangolin.exe"
  
SectionEnd

;--------------------------------
; uninstall

Section "Uninstall"
 
  ; Remove files and uninstaller
  Delete "$INSTDIR\*.*"

  ; Remove shortcuts, if any
  Delete "$SMPROGRAMS\Pangolin\*.*"
  Delete "$DESKTOP\Pangolin 代理.lnk"

  ; Remove directories used
  RMDir /r "$SMPROGRAMS\Pangolin"
  RMDir /r "$INSTDIR"

SectionEnd

