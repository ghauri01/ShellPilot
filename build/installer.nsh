; Adds the shellpilot CLI launcher's folder to the current user's PATH, so
; `shellpilot claude`/`codex`/`run` work from any terminal right after
; installing — without this, the CLI is bundled but unreachable, since
; nothing else registers it (see docs/AI-MCP.md).
;
; Deliberately HKCU only, never HKLM: this installer runs per-user
; (perMachine: false in electron-builder.yml), and writing to HKCU needs no
; admin rights.
;
; Deliberately does NOT remove the entry on uninstall. Splicing a substring
; back out of PATH is easy to get subtly wrong in NSIS string ops, and a
; broken splice would corrupt the user's PATH — a worse failure than leaving
; one stale, harmless entry pointing at a folder that no longer exists.
;
; A terminal window already open when you install will not see the new
; PATH — that's normal Windows behaviour for any environment-variable
; change, not specific to this script. Open a new one.

!macro customInstall
  ; asarUnpack (electron-builder.yml) puts bin/ under app.asar.unpacked, not
  ; under a plain "app" folder — that folder name only exists when asar
  ; packing is disabled entirely, which this build does not do.
  StrCpy $9 "$INSTDIR\resources\app.asar.unpacked\bin"
  ReadRegStr $8 HKCU "Environment" "Path"

  ; Search for ";$9;" inside ";$8;" (wrapped in ";" on both sides so this
  ; can't be fooled by one path being a prefix of another, e.g. C:\App vs
  ; C:\App2) by sliding a window of the needle's length across the haystack.
  StrCpy $7 ";$8;"
  StrCpy $6 ";$9;"
  StrLen $5 $6
  StrCpy $4 0

  shellpilot_path_scan:
    StrCpy $3 $7 $5 $4
    StrCmp $3 $6 shellpilot_path_present
    StrCmp $3 "" shellpilot_path_absent
    IntOp $4 $4 + 1
    Goto shellpilot_path_scan

  shellpilot_path_absent:
    StrCmp $8 "" shellpilot_path_empty shellpilot_path_append
    shellpilot_path_empty:
      StrCpy $8 "$9"
      Goto shellpilot_path_write
    shellpilot_path_append:
      StrCpy $8 "$8;$9"
    shellpilot_path_write:
      WriteRegExpandStr HKCU "Environment" "Path" "$8"
      ; HWND_BROADCAST = 0xFFFF, WM_SETTINGCHANGE = 0x001A — written as raw
      ; values so this doesn't depend on WinMessages.nsh being included.
      SendMessage 0xFFFF 0x001A 0 "STR:Environment" /TIMEOUT=5000

  shellpilot_path_present:
!macroend
