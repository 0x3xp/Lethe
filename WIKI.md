# Lethe — Technical Wiki

This document covers the full technical picture of Lethe: what it does, how it works, what it defeats, what detects it, and what it cannot do. It is written to be accurate, not promotional.

---

## Table of Contents

- [What Lethe Is](#what-lethe-is)
- [What Lethe Is Not](#what-lethe-is-not)
- [Architecture](#architecture)
- [Execution Chain and IRQL Model](#execution-chain-and-irql-model)
- [Capabilities](#capabilities)
  - [LetheCredDump](#lethcreddump)
  - [LetheTokenSteal](#lethetokensteal)
  - [LetheKillEDR](#lethkilledr)
- [Stealth Properties](#stealth-properties)
  - [PsLoadedModuleList Unlinking](#psloadedmodulelist-unlinking)
  - [PiDDBCacheTable Clearing](#piddbcachetable-clearing)
  - [Persistence](#persistence)
- [Detection Surface](#detection-surface)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Limitations](#limitations)
- [Lab Setup](#lab-setup)
- [Building](#building)
- [Usage](#usage)
- [References](#references)
- [Disclaimer](#disclaimer)

---

## What Lethe Is

Lethe is a **Windows kernel-mode implant** built as a research and red team tool. Its execution engine is the Windows **Deferred Procedure Call (DPC)** subsystem — specifically a `KTIMER` + `KDPC` + `IO_WORKITEM` chain that self-reschedules indefinitely without creating any userland threads or allocations.

The key property of this execution model is that it **does not surface in userland address spaces**. Tools that enumerate process memory — pe-sieve, Moneta, BeaconEye — work through `NtQueryVirtualMemory`, which enumerates a process's Virtual Address Descriptor (VAD) tree. Lethe's execution context lives in the kernel non-paged pool, which is not visible through that API.

Lethe combines several known kernel techniques — driver self-hiding, PiDDBCache manipulation, kernel credential dumping, token manipulation, and callback removal — into a single composed tool. The individual techniques are not new. The combination packaged as a single implant has not been published before in this form.

The technique used for credential dumping (`MmCopyVirtualMemory` from kernel context to read lsass) eliminates the standard detection surface for lsass access — no `OpenProcess` call, no `ReadProcessMemory` telemetry, no handle-based access observable from userland.

---

## What Lethe Is Not

Being precise about what Lethe does not do matters for setting accurate expectations.

**Lethe is not undetectable.** Kernel-level EDR components, hypervisor-based monitoring, and ETW kernel providers can detect Lethe's activity. Specifically, `PsSetCreateProcessNotifyRoutine` does not fire (Lethe creates no processes), but kernel ETW sessions and direct kernel memory inspection can reveal it.

**Lethe is not ready for production use without a BYOVD wrapper.** Windows enforces driver signing. Without an EV certificate or a BYOVD loader, `lethe.sys` will not load on any standard system. See [BYOVD.md](BYOVD.md) for a complete explanation.

**Lethe is not a C2 framework.** It has no network stack, no encryption, no implant tasking protocol beyond a local named pipe. It is an execution primitive and a set of kernel operations. Integration with a full C2 requires additional engineering.

**Lethe's credential dump is not a minidump.** `LetheCredDump` writes raw committed memory pages from lsass's virtual address space. The output is not directly parseable by pypykatz or Mimikatz without conversion to minidump format.

---

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                     lethe.sys                        │
│                                                      │
│  KTIMER ──fires──► KDPC ──queues──► IO_WORKITEM      │
│     ▲                                    │           │
│     └──────────── re-arm ◄───────────────┘           │
│                                                      │
│  Stealth:                                            │
│    PsLoadedModuleList  → unlinked at DriverEntry     │
│    PiDDBCacheTable     → entry cleared at load       │
│    Registry autostart  → written from kernel         │
│                                                      │
│  Operations (from IO_WORKITEM at PASSIVE_LEVEL):     │
│    LetheCredDump    → MmCopyVirtualMemory on lsass   │
│    LetheTokenSteal  → EPROCESS.Token swap            │
│    LetheKillEDR     → PspCreateProcessNotify nulling │
│    Pipe I/O         → ZwReadFile / ZwWriteFile       │
└──────────────────────────────────────────────────────┘
                          │
              \Device\NamedPipe\lethe
                          │
┌──────────────────────────────────────────────────────┐
│                    client.exe                        │
│  CreateNamedPipe → ConnectNamedPipe → command loop   │
└──────────────────────────────────────────────────────┘
```

---

## Execution Chain and IRQL Model

Windows kernel execution happens at **Interrupt Request Levels (IRQL)**. The IRQL dictates what a thread of execution may do — higher levels impose more restrictions.

```
PASSIVE_LEVEL (0)   Full capability — I/O, paged memory, blocking allowed
APC_LEVEL (1)       Normal thread APCs disabled
DISPATCH_LEVEL (2)  No paging, no blocking, no I/O — scheduler suspended
```

The DPC chain navigates these levels deliberately:

```
DriverEntry          PASSIVE_LEVEL   arms KTIMER, initializes KDPC
     ↓
KTIMER expires                       managed by kernel timer subsystem
     ↓
KDPC fires           DISPATCH_LEVEL  re-arms timer, queues IO_WORKITEM
     ↓
IO_WORKITEM runs     PASSIVE_LEVEL   executes all implant logic
```

The DPC itself does almost nothing — it re-arms the timer and queues the work item. This is deliberate: work at DISPATCH_LEVEL must be minimal and cannot perform I/O or access paged memory. The IO_WORKITEM runs on a system worker thread at PASSIVE_LEVEL, where all kernel I/O APIs are available.

The reason DPC is used rather than `PsCreateSystemThread` is not because DPC avoids all detection — it does not. The reason is that `PsSetCreateThreadNotifyRoutine` fires on every thread creation, including system threads, and the thread's start address is visible in kernel debuggers and process listings. A self-rescheduling timer-DPC pair has no equivalent notification mechanism.

---

## Capabilities

### LetheCredDump

Reads `lsass.exe` memory pages from kernel context using `MmCopyVirtualMemory` and writes them to disk.

**Standard userland lsass access (Mimikatz, ProcDump, Nanodump):**
```
attacker.exe
  └── OpenProcess(lsass, PROCESS_VM_READ)   ← handle table entry created
        └── ReadProcessMemory(lsass, ...)    ← ETW event fires
              └── MiniDumpWriteDump(...)     ← AV/EDR commonly blocks here
```

Every step generates telemetry. EDRs specifically watch for `OpenProcess` on lsass with `PROCESS_VM_READ` access. This is among the most-detected offensive techniques in the Windows ecosystem.

**Lethe CredDump:**
```
IO_WORKITEM (SYSTEM, PID 4)
  └── ZwQuerySystemInformation → enumerate processes, find lsass PID
        └── PsLookupProcessByProcessId → get lsass EPROCESS
              └── KeStackAttachProcess → enter lsass address space
                    └── ZwQueryVirtualMemory → enumerate committed regions
                          └── MmCopyVirtualMemory → copy pages to kernel buf
                                └── ZwWriteFile → write to C:\Windows\Temp\lsass.dmp
```

No handle is opened from userland. `ReadProcessMemory` is never called. The operation is attributed to the System process. On a system without kernel-level lsass protection (RunAsPPL), this completes without triggering standard EDR telemetry.

**Caveats:** The output is raw memory pages, not minidump format. ParseR tools expect `MINIDUMP_HEADER`. The credential material is present in the dump but requires a tool capable of parsing raw memory (Volatility with the lsass plugin, or manual conversion to minidump format).

**Output:** `C:\Windows\Temp\lsass.dmp`

---

### LetheTokenSteal

Copies the `SYSTEM` process token to a target process by directly overwriting the `Token` field in the target's `EPROCESS` structure.

The `EPROCESS` structure holds a reference to a process's primary access token as an `EX_FAST_REF` — a pointer with the lower 4 bits used as a reference count. Swapping this pointer to point at the System process's token gives the target process SYSTEM-level privileges.

```
Standard token manipulation (userland):
  OpenProcess → OpenProcessToken → DuplicateTokenEx → ImpersonateLoggedOnUser
  ↑ multiple handle operations, multiple audit events

Lethe TokenSteal:
  PsInitialSystemProcess → PsReferencePrimaryToken → direct EPROCESS.Token write
  ↑ one pointer swap, no handles, no audit events from userland
```

The token offset in `EPROCESS` is version-specific. Lethe uses `0x4B8` for Windows 10 19041. This must be verified for other versions with `dt nt!_EPROCESS` in WinDbg.

**Usage:** `client.exe tokensteal <pid>`

---

### LetheKillEDR

Removes callback entries from `PspCreateProcessNotifyRoutine` — the kernel array that notifies registered drivers of process creation events.

EDR products register callbacks via `PsSetCreateProcessNotifyRoutine`, `PsSetCreateThreadNotifyRoutine`, and `PsSetLoadImageNotifyRoutine` to receive kernel telemetry. These are stored in unexported arrays in ntoskrnl. Lethe locates the array via pattern scan, walks each entry, identifies which module owns the callback address, and nulls entries belonging to the target.

The effect: the EDR process continues running but stops receiving kernel notifications for process creation, thread creation, and image loads on that machine. From the EDR's dashboard it may appear operational. It is not receiving events.

This does not disable all EDR capability. Network telemetry, file system minifilter callbacks, and other monitoring mechanisms are unaffected by this operation alone.

**Usage:** `client.exe killedr WdFilter.sys`

---

## Stealth Properties

### PsLoadedModuleList Unlinking

Windows maintains a doubly linked list, `PsLoadedModuleList`, of all loaded kernel modules. Each entry is an `LDR_DATA_TABLE_ENTRY`. Tools that enumerate loaded drivers — `sc query`, `driverquery`, `EnumDeviceDrivers()`, WinDbg's `lm` command — walk this list.

Lethe removes its own entry using `RemoveEntryList` at DriverEntry completion:

```
Before:
  [ntoskrnl] ↔ [hal] ↔ [lethe.sys] ↔ [disk.sys]

After RemoveEntryList():
  [ntoskrnl] ↔ [hal] ↔ [disk.sys]
  lethe.sys still loaded in memory — just not in the list
```

The `lethe.sys` pages remain mapped. A kernel debugger with direct memory access, or a driver that scans the non-paged pool directly, can still find it. The unlink defeats enumeration-based detection, not inspection-based detection.

### PiDDBCacheTable Clearing

Windows 10 introduced `PiDDBCacheTable`, an AVL tree in ntoskrnl that records every driver that has loaded since boot, indexed by `TimeDateStamp` from the PE header. This table persists even after a driver unlinks itself from `PsLoadedModuleList`. EDRs and forensic tools use it to detect drivers that loaded and then hid themselves.

Lethe locates `PiDDBCacheTable` by scanning ntoskrnl's `.text` section for a known LEA instruction pattern that references the table, decodes the RIP-relative offset, and removes its own entry using `RtlEnumerateGenericTableAvl` + `RtlDeleteElementGenericTableAvl`.

After this operation, no kernel tracking structure records that `lethe.sys` was ever loaded. This is effective against tools that rely on the standard kernel enumeration API. It does not defeat a hypervisor-level audit or a tamper-proof logging system that captured the load event at boot.

### Persistence

Lethe writes its own service registry key from kernel using `ZwCreateKey` and `ZwSetValueKey`:

```
HKLM\SYSTEM\CurrentControlSet\Services\Lethe
  ImagePath    = \??\C:\Lethe\lethe.sys
  Type         = 1   (SERVICE_KERNEL_DRIVER)
  Start        = 2   (SERVICE_AUTO_START)
  ErrorControl = 1
```

`Start = 2` causes Windows to load the driver during boot, before any user session starts and before most EDR agents initialize their kernel components. The registry key itself is visible to any tool that reads the services hive — it is not hidden. Persistence relies on the driver loading and then hiding itself, not on hiding the registry key.

---

## Detection Surface

Lethe reduces the detection surface compared to userland implants. It does not eliminate it. The following is an honest accounting of what can and cannot detect it.

### What Standard Userland Tools Cannot See

| Tool | Why It Misses Lethe |
|---|---|
| pe-sieve | Scans process VADs via NtQueryVirtualMemory — kernel pool not enumerated |
| Moneta | Same mechanism as pe-sieve |
| BeaconEye | Scans heap allocations for beacon config — no heap, no beacon |
| Hunt-Sleeping-Beacons | Looks for private RX regions in processes — no such region |
| sc query / driverquery | Enumerate PsLoadedModuleList — unlinked |
| WinDbg lm | Enumerates PsLoadedModuleList — unlinked |
| Task Manager | No suspicious threads or processes |

### What Can Detect Lethe

| Method | Mechanism |
|---|---|
| Kernel ETW sessions | Some kernel operations emit ETW events even from kernel callers |
| Direct pool scan | Tools that scan non-paged pool for specific patterns or pool tags (`htL`) |
| WinDbg `!dpcs` | Lists pending DPCs — Lethe's KDPC may appear in the queue |
| PiDDBCacheTable integrity check | If captured before Lethe clears it, or if a hypervisor logged the load |
| Hypervisor-based monitoring | VBS/HVCI environments with kernel event logging can observe driver loads regardless of in-OS hiding |
| Registry inspection | The persistence key is visible and not hidden |
| Named pipe enumeration | `\Device\NamedPipe\lethe` is visible to kernel-level pipe enumeration |
| Memory forensics (Volatility) | Pool tag scanning and KPCR-based driver enumeration can find Lethe independently of PsLoadedModuleList |

---

## MITRE ATT&CK Mapping

| Technique | ID | Implementation |
|---|---|---|
| Boot or Logon Autostart: Kernel Modules | [T1547.006](https://attack.mitre.org/techniques/T1547/006/) | Registry autostart key written from kernel via ZwCreateKey |
| Rootkit | [T1014](https://attack.mitre.org/techniques/T1014/) | PsLoadedModuleList unlink, PiDDBCacheTable removal |
| Indicator Removal: Timestomp | [T1070.006](https://attack.mitre.org/techniques/T1070/006/) | PiDDBCacheTable entry removal erases driver load timestamp record |
| Masquerading | [T1036](https://attack.mitre.org/techniques/T1036/) | All activity attributed to SYSTEM process (PID 4) |
| OS Credential Dumping: LSASS Memory | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | MmCopyVirtualMemory reads lsass from kernel — no OpenProcess, no ReadProcessMemory |
| Access Token Manipulation | [T1134](https://attack.mitre.org/techniques/T1134/) | Direct EPROCESS.Token pointer swap from kernel |
| Impair Defenses: Disable or Modify Tools | [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | PspCreateProcessNotifyRoutine array entry nulling |
| Native API | [T1106](https://attack.mitre.org/techniques/T1106/) | Exclusive use of Zw*/Ps*/Mm*/Ke* kernel APIs |
| Create or Modify System Process: Windows Service | [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | Service registry key written from DriverEntry |

---

## Limitations

### Driver Signing — Primary Constraint

Windows requires all kernel drivers to carry a valid **Extended Validation (EV) code signing certificate** on systems with Secure Boot and driver signing enforcement enabled. Loading an unsigned driver fails with error 577 (`ERROR_INVALID_IMAGE_HASH`).

**Test environments:** Enable test signing and self-sign with a local certificate:
```bat
bcdedit /set testsigning on
```

**Production systems:** Requires a BYOVD loader or a legitimately obtained EV certificate. See [BYOVD.md](BYOVD.md).

### HVCI — Growing Constraint

Hypervisor-Protected Code Integrity (HVCI) runs kernel code integrity checks inside a hypervisor-isolated environment, preventing any unsigned kernel code from executing regardless of test signing or BYOVD attempts. Even if a BYOVD loader gains kernel write access, it cannot execute arbitrary code in a kernel context under HVCI — it can only write data, not cause unsigned code to run.

HVCI has historically been enabled only on clean Windows 11 installs and Secured-core PCs. As of October 2026, Microsoft is rolling out automatic HVCI enablement to Windows 11 machines via Windows Update on eligible hardware. Enterprise environments managed via Group Policy or Intune can override this. Windows 10 machines are unaffected.

The practical implication: **HVCI adoption is increasing**, and BYOVD techniques that work today will encounter this mitigation more frequently going forward.

### Minidump Format

`LetheCredDump` does not produce a valid Windows minidump. The output is a sequential dump of committed memory pages from lsass's virtual address space. Pypykatz and Mimikatz require `MINIDUMP_HEADER`. Conversion is not currently implemented.

### Named Pipe Architecture

Lethe's named pipe (`\Device\NamedPipe\lethe`) accepts one client at a time. A second `client.exe` instance cannot connect while one is active.

### EPROCESS Offset Dependency

`LetheTokenSteal` uses a hardcoded EPROCESS `Token` field offset (`0x4B8`) verified for Windows 10 19041. Other Windows versions use different offsets. This must be checked with `dt nt!_EPROCESS` before use on a different build.

---

## Lab Setup

### Requirements

```
Host (development + WinDbg):
  Windows 10/11 x64
  Visual Studio Build Tools 2022
  WDK 10.0.28000.0
  WinDbg Preview

Guest VM (target):
  VMware Workstation
  Windows 10 x64 (19041 recommended)
  2GB RAM, 40GB disk
  Test signing enabled
  KDNET debugging enabled
  Windows Defender disabled (optional, for clean testing)
```

### VM Preparation

Run as Administrator in the VM, then reboot:

```bat
:: Test signing
bcdedit /set testsigning on

:: KDNET — replace 192.168.x.x with your host IP
bcdedit /debug on
bcdedit /dbgsettings net hostip:192.168.x.x port:50000 key:1.2.3.4
```

### WinDbg Connection (Host)

```
File → Attach to kernel → Net
  Port: 50000
  Key:  1.2.3.4
```

### Certificate Setup (VM)

```powershell
$cert = New-SelfSignedCertificate `
    -Subject "CN=LetheTestCert" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -Type CodeSigningCert

Export-Certificate -Cert $cert -FilePath "C:\LetheTestCert.cer"

Import-Certificate -FilePath "C:\LetheTestCert.cer" `
    -CertStoreLocation "Cert:\LocalMachine\Root"
Import-Certificate -FilePath "C:\LetheTestCert.cer" `
    -CertStoreLocation "Cert:\LocalMachine\TrustedPublisher"
```

### Signing the Driver (VM, after each build)

```bat
set SIGNTOOL="C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe"
%SIGNTOOL% sign /fd sha256 /n "LetheTestCert" C:\Lethe\lethe.sys
```

---

## Building

### Project Structure

```
Lethe/
├── assets/
│   └── banner.png
├── driver/
│   ├── lethe.c
│   ├── lethe.h
│   └── build.bat
├── client/
│   └── client.c
├── scripts/
│   ├── load.bat
│   └── unload.bat
├── bin/
│   ├── Lethe.sys
│   └── client.exe
├── README.md
├── WIKI.md
├── BYOVD.md
└── LICENSE
```

### Driver

From the x64 Native Tools Command Prompt:

```bat
cd driver
build.bat
```

### Client

```bat
cl.exe client.c /Fe:client.exe /link kernel32.lib
```

---

## Usage

Run `client.exe` first. It creates the named pipe server. The driver connects on first DPC tick after load.

```bat
:: Alive check
client.exe ping

:: Dump lsass memory to C:\Windows\Temp\lsass.dmp
client.exe creddump

:: Copy SYSTEM token into target process
client.exe tokensteal <pid>

:: Remove EDR kernel callbacks
client.exe killedr WdFilter.sys
```

### Loading the Driver

```bat
sc create Lethe type= kernel binPath= C:\Lethe\lethe.sys
sc start Lethe
```

### Verifying the Hide

```bat
:: Should return nothing
sc query type= driver state= all | findstr /i lethe
driverquery | findstr /i lethe

:: Persistence key should exist
reg query "HKLM\SYSTEM\CurrentControlSet\Services\Lethe"
```

---

## References

- [Windows Internals, 7th Ed. — Yosifovich, Ionescu, Russinovich, Solomon](https://learn.microsoft.com/en-us/sysinternals/resources/windows-internals)
- [WDK API Reference — Microsoft Docs](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/)
- [Deferred Procedure Calls — Microsoft Docs](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/introduction-to-dpcs)
- [MITRE ATT&CK Enterprise — attack.mitre.org](https://attack.mitre.org/techniques/enterprise/)
- [loldrivers.io — Vulnerable Driver Database](https://www.loldrivers.io)
- [OSR Online — Kernel Driver Resources](https://www.osronline.com)
- [ReactOS Source — Kernel Reference](https://github.com/reactos/reactos)
- [Exploring Vulnerable Windows Drivers — Cisco Talos, 2024](https://blog.talosintelligence.com/exploring-vulnerable-windows-drivers/)
- [Breaking Boundaries: Vulnerable Drivers — Check Point Research, 2024](https://research.checkpoint.com/2024/breaking-boundaries-investigating-vulnerable-drivers-and-mitigating-risks/)
- [ESET Research: BYOVD](https://www.eset.com/int/about/newsroom/press-releases/research/esets-research-into-bring-your-own-vulnerable-driver-details-attacks-on-drivers-in-windows-core/)
- [VBS and HVCI — Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/?p=92539)

---

## Disclaimer

Lethe is a security research tool. It is intended for authorized penetration testing, red team operations, and security research in controlled environments. Use against systems you do not own or do not have explicit written authorization to test is illegal under computer fraud laws in most jurisdictions.

The techniques documented here are understood by the security research community and described in academic and industry literature. Publishing them serves the goal of helping defenders understand and detect kernel-level threats.

---

<div align="center">

*Λήθη — river of oblivion*

---

Built by [0x3xp](https://0x3xp.github.io)

[![X](https://img.shields.io/badge/X-0xmrlowlwvel-000000?style=flat&logo=x&logoColor=white)](https://x.com/0xmrlowlwvel)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-piyushaakash-0A66C2?style=flat&logo=linkedin&logoColor=white)](https://linkedin.com/in/piyushaakash)
[![YouTube](https://img.shields.io/badge/YouTube-infoseclk-FF0000?style=flat&logo=youtube&logoColor=white)](https://youtube.com/@infoseclk)

</div>
