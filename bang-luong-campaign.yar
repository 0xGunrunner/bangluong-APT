/*
   YARA rules — "Bảng lương" / Winos 4.0-style campaign
   Static analysis 2026-11-17. Validated against the original samples:
   every rule fires on its target, no hits on the clean vendor-signed
   components (WeChatAppEx.exe, lua51.dll, Microsoft runtimes).

   Note: set.log (RC4-encrypted shellcode, key s3ch0bachky) is intentionally
   not string-matchable — match the decrypted blob or by hash instead.
*/

rule WinRAR_SFX_BangLuong_Dropper
{
    meta:
        family = "Winos4.0-style / Bang Luong campaign"
        description = "WinRAR SFX dropper with silent auto-exec script into fake AppData path"
        reference = "sha256 f8ef62e4276e61b01435874c2385ba8b80d8b98d7b7d056f2f3ddffd27a3c5a8"
    strings:
        $path   = "Path=C:\\ProgramLog\\Windows\\AppData\\Log" ascii
        $setup1 = "Setup=WeChatAppEx.exe" ascii
        $setup2 = "Setup=TGFile.exe hide.log" ascii
        $setup3 = "Setup=TGFile.exe regite.log" ascii
        $setup4 = "Setup=TGFile.exe new.jpg" ascii
        $silent = "Silent=1" ascii
        $pdb    = "D:\\Projects\\WinRAR\\sfx\\build\\sfxrar64\\Release\\sfxrar.pdb" ascii
    condition:
        uint16(0) == 0x5A4D and $pdb and 3 of ($path, $setup*, $silent)
}

rule Driver_TGSoft_ProcKill
{
    meta:
        family = "Winos4.0-style / Bang Luong campaign"
        description = "Signed kernel process-kill driver (\\Device\\ProcKill, IOCTL 0x80001c00)"
        note = "device/symlink names are stored UTF-16 in the driver"
        reference = "sha256 2451129aedd9d7a60e7a35639e753fe79887ae075d65872181debb9adba69dac"
    strings:
        $dev    = "\\Device\\ProcKill" wide ascii
        $link   = "\\??\\ProcKill" wide ascii
        $zwt    = "ZwTerminateProcess" ascii
        $anneng = "Anneng electronic Co. Ltd." ascii
        $pdb    = "MyDriver1-master" ascii
    condition:
        uint16(0) == 0x5A4D and 1 of ($dev, $link) and $zwt and filesize < 100KB and any of ($anneng, $pdb)
}

rule LuaJIT_Plugin_BangLuong
{
    meta:
        family = "Winos4.0-style / Bang Luong campaign"
        description = "LuaJIT plugins (bytecode or source) and scriptlet of the campaign"
        note = "matches hide.log, regite.log (bytecode), new.jpg (source), log.s (scriptlet)"
        reference = "keys: TGFile_ShellcodeMutex / TGFile_SetupMutex / s3ch0bachky"
    strings:
        $ljmagic = { 1B 4C 4A 02 }
        $mutex1  = "Global\\TGFile_ShellcodeMutex" ascii
        $mutex2  = "Local\\TGFile_SetupMutex" ascii
        $rc4key  = "s3ch0bachky" ascii
        $task    = "OneDirverUpdata" ascii
        $typelib = "{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}" ascii
        $setlog  = "C:\\ProgramLog\\Windows\\AppData\\Log\\set.log" ascii
        $tgfile  = "TGFile.exe" ascii
        $hidelog = "hide.log" ascii
    condition:
        filesize < 500KB and 2 of them
}

rule Loader_XwebElf_Orchestrator
{
    meta:
        family = "Winos4.0-style / Bang Luong campaign"
        description = "Unsigned orchestrator DLL sideloaded by legit WeChatAppEx.exe; service installs TG_Soft.sys"
        reference = "sha256 734b6729731d85988627e84b01d22298c04378e4949c5e69c34237a4574f3dcb"
    strings:
        $cuhj = "cuhjctyasbdtas.dll" ascii
        $sbie = "SbieDll_GetServiceRegistryValue" ascii
        $d1   = "ABORT: driver load failed" ascii
        $d2   = "Driver file NOT found: %s" ascii
        $d3   = "Service state=%lu (4=RUNNING)" ascii
        $d4   = "ChangeServiceConfigW OK, new ImagePath: %s" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2MB and 1 of ($cuhj, $sbie) and 1 of ($d*)
}

rule RAT_BangLuong_EmbeddedDLL
{
    meta:
        family = "Winos4.0-style / Bang Luong campaign"
        description = "Reflectively-loaded RAT DLL (pinyin export zidingyixiugaidaochuhanshu)"
        reference = "sha256 dbb168e93248ccc39f4ab667510ef68401fcbd93d7ab012c2ae502ef9204bedf"
    strings:
        $exp = "zidingyixiugaidaochuhanshu" ascii
    condition:
        uint16(0) == 0x5A4D and $exp
}

rule Dropper_Carved_Shellcode_BangLuong
{
    meta:
        family = "Winos4.0-style / Bang Luong campaign"
        description = "RC4-decrypted PIC shellcode container (call $+5 prologue, 'dave' tail marker)"
        reference = "sha256 5ba83d20a428042542e539662330624961f55c5a5c05aa9431c45df4b4ecba29"
    strings:
        $dave = "dave" ascii
        $mz   = "!This program cannot be run in DOS mode." ascii
    condition:
        filesize > 100KB and $mz and $dave at (filesize-4)
}
