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

# Approach
Stuff.
