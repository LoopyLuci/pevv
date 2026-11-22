; NSIS installer hooks for PEVV (Tauri `installerHooks`).
; Registers / removes the browser native-messaging host (per user, HKCU) so the PEVV
; extension can link to the desktop app. The app does the work: `--register-link`
; honours the "Browser extension link" setting, `--unregister-link` always removes.
; `--add-path` / `--remove-path` put the install folder (where `pevv.exe`, the command-line
; tool, lives) on the user's PATH and take it off again.

!macro NSIS_HOOK_POSTINSTALL
  nsExec::Exec '"$INSTDIR\${MAINBINARYNAME}.exe" --register-link'
  Pop $0
  nsExec::Exec '"$INSTDIR\${MAINBINARYNAME}.exe" --add-path'
  Pop $0
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  nsExec::Exec '"$INSTDIR\${MAINBINARYNAME}.exe" --unregister-link'
  Pop $0
  nsExec::Exec '"$INSTDIR\${MAINBINARYNAME}.exe" --remove-path'
  Pop $0
!macroend
