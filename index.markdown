---
layout: default
---
<br/>

# What Is This?
This is the story of getting shellcode execution and a reverse shell on a hardened host in a well-managed (and well-funded) network. Additional odds and ends related to binary exploitation may also make an appearance.

<hr/>

# Environment
The target host is a fully-patched Windows 10 workstation with Carbon Black and Cortex XDR.
- <b>Carbon Black</b>: Aggressive software restriction - prevents execution of unknown executables, including DLLs, VB/JS scripts, and drivers. PowerShell is allowed since it is part of the Windows base system, but see below.
- <b>Cortex XDR</b>: Sophisticated endpoint protection, very effective at detecting and blocking threats.

<hr/>

# Carbon Black Driver
Carbon Black's kernel driver (cbk7.sys), which is loaded at boot time, is able to inspect process creation by calling the `PsSetCreateProcessNotifyRoutine()` Windows API. From MSDN: "The PsSetCreateProcessNotifyRoutine routine adds a driver-supplied callback routine to, or removes it from, a list of routines to be called whenever a process is created or deleted."

To monitor thread creation and image loads, it calls two more similar functions: `PsSetCreateThreadNotifyRoutine()` and `PsSetLoadImageNotifyRoutine()`. (An "image" in this context usually just means a DLL.)
When the callback function receives a notification, it performs several checks to determine whether it should allow or block the request. Unknown and non-allowlisted executables will always be blocked.

![cbk7.sys](/images/psset1.png)
<p style="text-align: center; font-size: 12px;">Disassembly pseudocode of cbk7.sys calling PsSetCreateProcessNotifyRoutine()</p>

<hr/>

# Approach
The goal is to run arbitrary code on the host to get a reverse shell. Since custom executables, DLLs, and scripts are blocked by Carbon Black, two possibilities come to mind: PowerShell and process injection.

<hr/>

# PowerShell
The general approach with PowerShell is to import Windows API functions using the `Add-Type` cmdlet, then call them as usual from within PowerShell.

```powershell
Add-Type @'
using System;
using System.Runtime.InteropServices;
public class Kernel32 {
    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, uint bInheritHandle, uint dwProcessId);
    ...etc...
}
'@
...

$Flags = 0x2a # (PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE)
$hProcess = [Kernel32]::OpenProcess($Flags, $False, $Notepad.Id)
```
<p style="text-align: center; font-size: 12px;">Importing and calling Windows API functions in PowerShell</p>

While Carbon Black generally leaves PowerShell alone because it is an allowlisted application, Cortex XDR does not. In fact, the moment the `Add-Type` cmdlet is executed with the `DllImport` directive, Cortex XDR kills the PowerShell process. It may be possible to obfuscate the `Add-Type` arguments, but this seems like a losing battle.

<hr/>

# Process Injection
