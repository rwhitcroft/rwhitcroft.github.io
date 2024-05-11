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
The goal is to run arbitrary code on the host to get a reverse shell. Since custom executables, DLLs, and scripts are blocked by Carbon Black, we can try injecting code into an existing process (or one that we're allowed to launch such as notepad since it's a Windows base application). This method is sometimes called "fork & run" where a process is started whose only purpose is to receive an injection of code.

This technique has been known for years and usually consists of the following steps:
- `OpenProcess()` to get a handle to the target process.
- `VirtualAllocEx()` to allocate a read-write-execute buffer in the target process.
- `WriteProcessMemory()` to write the shellcode into the newly-allocated buffer in the target process.
- `CreateRemoteThread()` to create a thread in the target process whose entrypoint is the shellcode buffer.

Because this technique is so well-known, nearly all AV/EDR products will closely monitor these functions using hooks. Calling these four functions in sequence will almost always get you caught, so it's better to find different ways to achieve the same outcome. As we'll see, obtaining a reverse shell under the watchful eyes of Carbon Black and Cortex XDR was possible using only two of the four functions above (`OpenProcess()` and `WriteProcessMemory()`), lowering the likelihood of detection.

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
    ...snip...
}
'@
...snip...

$Flags = 0x2a # aka (PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE)
$hProcess = [Kernel32]::OpenProcess($Flags, $False, $Notepad.Id)
```
<p style="text-align: center; font-size: 12px;">Importing and calling Windows API functions in PowerShell</p>

While Carbon Black generally leaves PowerShell alone because it is an allowlisted application, Cortex does not. In fact, the moment the `Add-Type` cmdlet is executed with the `DllImport` directive, Cortex kills the PowerShell process. It may be possible to obfuscate the `Add-Type` arguments, but this seems like a losing battle.

<hr/>

# The Story So Far
We can't run exes. We can't load DLLs. We can't use vbscript or jscript. We can't use PowerShell to import Windows functions. Fortunately, there is one avenue left to explore that may allow us import and call the Windows APIs above needed to inject code.

<hr/>

# InstallUtil
`InstallUtil` is a Windows base application that is used for installing and uninstalling software. The only functionality we care about is its `/u` option which is used to uninstall applications.

When applications are built in C#, developers have the ability to add in two special functions: `Install()` and `Uninstall()`. These functions are never called internally, but instead are used to perform any initialization needed when installing, and any cleanup needed when uninstalling. We will focus on `Uninstall()` because it does not require administrator privileges.

We are not concerned with any actual install/uninstall stuff - the only reason this is useful is because it should let us run arbitrary C# code to perform the process injection. Even though we can't run our exe, we can still put code in its `Uninstall()` function and then use `InstallUtil /u app.exe` to force Windows to call it for us, bypassing Carbon Black's restrictions.

# PoC #1

```csharp
using System;
using System.Collections;
using System.Diagnostics;
using System.Configuration.Install;
using System.IO;
using System.Runtime.InteropServices;

namespace IU
{
    internal class Program
    {
        static void Main(string[] args)
        {
            // empty Main - never called
        }
    }

    [System.ComponentModel.RunInstaller(true)]
    public class Bypass : System.Configuration.Install.Installer
    {
        // Uninstall() gets called by InstallUtil when /u is specified
        public override void Uninstall(IDictionary savedState)
        {
            Process p = new Process();
            p.StartInfo.FileName = "c:\\windows\\system32\\notepad.exe";
            p.StartInfo.CreateNoWindow = false;
            p.Start();
        }
    }
}
```

If we build this app, upload it to the target system, then do `installutil /u app.exe`, we see a new instance of notepad.exe pop up, proving that the `Uninstall()` function was executed.

