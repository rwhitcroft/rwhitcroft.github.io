---
layout: default
---
<br/>

# What Is This?
This is the story of getting shellcode execution and a reverse shell on a hardened host in a well-managed (and well-funded) network. Additional odds and ends related to binary exploitation may also make an appearance.

# Environment
The target host is a fully-patched Windows 10 workstation with Carbon Black and Cortex XDR.
- <b>Carbon Black</b>: Aggressive software restriction - prevents execution of unknown executables, including DLLs, VB/JS scripts, and drivers. PowerShell is allowed since it is part of the Windows base system, but see below.
- <b>Cortex XDR</b>: Sophisticated endpoint protection, very effective at detecting and blocking threats.

# Carbon Black Driver
Carbon Black's kernel driver (cbk7.sys), which is loaded at boot time, is able to inspect process creation by calling the `PsSetCreateProcessNotifyRoutine()` Windows API. From MSDN: "The PsSetCreateProcessNotifyRoutine routine adds a driver-supplied callback routine to, or removes it from, a list of routines to be called whenever a process is created or deleted."

To monitor thread creation and image loads, it calls two more similar functions: `PsSetCreateThreadNotifyRoutine()` and `PsSetLoadImageNotifyRoutine()`. (An "image" in this context usually just means a DLL.)
When the callback function receives a notification, it performs several checks to determine whether it should allow or block the request.

![cbk7.sys](/images/psset1.png)
<p style="text-align: center;">Disassembly of cbk7.sys calling PsSetCreateProcessNotifyRoutine()</p>

# Approach
The goal is to run arbitrary code on the host to get a reverse shell. Since custom executables, DLLs, and scripts are blocked by Carbon Black, 