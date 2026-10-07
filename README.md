<div align="center">
  <img src="assets/banner.png" alt="Lethe" width="100%"/>
</div>

<br>

<div align="center">

[![License](https://img.shields.io/badge/license-MIT-blue.svg)]()
[![Platform](https://img.shields.io/badge/platform-Windows%20x64-lightgrey.svg)]()
[![Kernel](https://img.shields.io/badge/mode-kernel-red.svg)]()

</div>

---

**Lethe** (Λήθη) is a kernel-mode implant that uses the Windows **Deferred Procedure Call (DPC)** subsystem as its primary execution engine. It performs offensive operations — credential dumping, token manipulation, EDR silencing — entirely from kernel context. No userland allocations. No threads. Everything attributed to SYSTEM.

Named after the Greek river of oblivion. What passes through it is forgotten.

---

## How It Works

A `KTIMER` fires on a configurable interval, queuing a `KDPC`, which queues an `IO_WORKITEM` into the system worker thread pool. All implant logic runs inside the work item at `PASSIVE_LEVEL`. The timer re-arms itself on every tick — indefinite, autonomous, no operator interaction required.

```
Standard implant:   VirtualAllocEx → WriteProcessMemory → CreateRemoteThread
                    ↑ all monitored, all attributed to attacker process

Lethe:              KTIMER → KDPC → IO_WORKITEM
                    ↑ no allocation, no thread, attributed to SYSTEM (PID 4)
```

---

## Capabilities

| Command | Description | MITRE |
|---|---|---|
| `ping` | Alive check | — |
| `creddump` | Dump lsass memory via `MmCopyVirtualMemory` — no `OpenProcess`, no `ReadProcessMemory` | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) |
| `tokensteal <pid>` | Copy SYSTEM token directly into target EPROCESS | [T1134](https://attack.mitre.org/techniques/T1134/) |
| `killedr <name.sys>` | Remove EDR kernel callbacks from `PspCreateProcessNotifyRoutine` | [T1562.001](https://attack.mitre.org/techniques/T1562/001/) |

---

## Stealth

- Unlinks from `PsLoadedModuleList` → invisible to `sc query`, `driverquery`, `EnumDeviceDrivers()`
- Clears `PiDDBCacheTable` entry → no driver load timestamp remains
- Lives in non-paged kernel pool → invisible to `NtQueryVirtualMemory`, pe-sieve, Moneta, BeaconEye
- No threads created → no `PsSetCreateThreadNotifyRoutine` event
- Registry autostart → loads before EDR at boot

---

## Requirements

```
Windows 10/11 x64
WDK 10.0.28000.0
Visual Studio Build Tools 2022
Test signing enabled (lab) or BYOVD loader (production)
```

---

## Build

```bat
:: Driver
cd driver
build.bat

:: Client
cl.exe client.c /Fe:client.exe /link kernel32.lib
```

Sign `lethe.sys` with a test certificate before loading. See [WIKI.md](WIKI.md) for full lab setup.

---

## Usage

Run `client.exe` first — it creates the named pipe. Then load the driver.

```bat
client.exe ping
client.exe creddump
client.exe tokensteal 1234
client.exe killedr WdFilter.sys
```

---

## MITRE ATT&CK

[T1547.006](https://attack.mitre.org/techniques/T1547/006/) · 
[T1014](https://attack.mitre.org/techniques/T1014/) · 
[T1070.006](https://attack.mitre.org/techniques/T1070/006/) · 
[T1003.001](https://attack.mitre.org/techniques/T1003/001/) · 
[T1134](https://attack.mitre.org/techniques/T1134/) · 
[T1562.001](https://attack.mitre.org/techniques/T1562/001/) · 
[T1106](https://attack.mitre.org/techniques/T1106/) · 
[T1543.003](https://attack.mitre.org/techniques/T1543/003/)

Full mapping and detection opportunities in [WIKI.md](WIKI.md).

---

## Limitations

- Requires test signing (`bcdedit /set testsigning on`) in lab environments
- Blocked by HVCI (Hypervisor-Protected Code Integrity)
- Production deployment requires a BYOVD wrapper — see [BYOVD.md](BYOVD.md)
- `creddump` produces raw memory pages, not minidump format

---

## Documentation

| Document | Description |
|---|---|
| [WIKI.md](WIKI.md) | Full technical documentation, lab setup, detection opportunities |
| [BYOVD.md](BYOVD.md) | Limitations, BYOVD deployment path, HVCI mitigations |

---

<div align="center">

*Λήθη — river of oblivion*

---

Built by [0x3xp](https://0x3xp.github.io)

[![X](https://img.shields.io/badge/X-0xmrlowlwvel-000000?style=flat&logo=x&logoColor=white)](https://x.com/0xmrlowlwvel)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-piyushaakash-0A66C2?style=flat&logo=linkedin&logoColor=white)](https://linkedin.com/in/piyushaakash)
[![YouTube](https://img.shields.io/badge/YouTube-infoseclk-FF0000?style=flat&logo=youtube&logoColor=white)](https://youtube.com/@infoseclk)

</div>
