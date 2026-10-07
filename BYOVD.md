# BYOVD — Lethe Deployment and Limitations

This document explains why Lethe cannot load on production systems without additional tooling, what BYOVD is and how it works, and what the realistic deployment path looks like for an operator using Lethe in an engagement. It also covers the mitigations that limit BYOVD and how that changes the operational picture.

---

## Table of Contents

- [Why Lethe Cannot Load Without BYOVD](#why-lethe-cannot-load-without-byovd)
- [What BYOVD Is](#what-byovd-is)
- [How BYOVD Works Technically](#how-byovd-works-technically)
- [Deploying Lethe via BYOVD](#deploying-lethe-via-byovd)
- [Real-World BYOVD Usage](#real-world-byovd-usage)
- [Mitigations That Block BYOVD](#mitigations-that-block-byovd)
- [HVCI and Its Growing Reach](#hvci-and-its-growing-reach)
- [Honest Assessment of Operational Viability](#honest-assessment-of-operational-viability)
- [References](#references)

---

## Why Lethe Cannot Load Without BYOVD

Since Windows Vista, Microsoft has enforced **Kernel Mode Code Signing (KMCS)**. Any driver loaded into the Windows kernel must carry a valid digital signature issued by a trusted Certificate Authority. On 64-bit systems with Secure Boot enabled, this is enforced at the hardware and firmware level.

When you run `sc start Lethe` with an unsigned or self-signed driver on a standard system, Windows returns error 577:

```
ERROR_INVALID_IMAGE_HASH (577)
Windows cannot verify the digital signature for this file.
```

The signing requirement creates two paths to loading an unsigned driver in a real environment:

1. **Obtain an EV code signing certificate** issued by a trusted CA. These require identity verification and cost several hundred dollars per year. They can be revoked when abused.

2. **BYOVD**: exploit a signed, trusted driver that already has kernel access to load your unsigned driver.

Lethe is a research tool built for test environments with test signing enabled. For production deployment, BYOVD is the realistic path. This document covers option 2.

---

## What BYOVD Is

**Bring Your Own Vulnerable Driver** (BYOVD) is a post-exploitation technique in which an attacker intentionally deploys a known-vulnerable but legitimately signed kernel driver onto a target system, exploits a vulnerability in that driver to gain kernel-mode code execution or arbitrary kernel memory access, and then uses that access to load or execute additional unsigned kernel code.

The technique is documented in the MITRE ATT&CK framework under [T1068 — Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/) and is observed regularly in real-world threat actor campaigns.

The core insight: Windows trusts the digital signature of the vulnerable driver. The driver loads. Once loaded, the driver's internal vulnerability gives the attacker kernel-level capabilities that Windows's signing enforcement cannot block — because the driver itself is trusted.

---

## How BYOVD Works Technically

### Step 1 — Choose a Vulnerable Driver

Vulnerable drivers fall into a few categories of vulnerability:

- **Arbitrary kernel memory read/write**: the driver exposes an IOCTL that reads or writes to an arbitrary kernel address supplied by the caller. No bounds checking. The caller can write to any kernel memory.
- **Arbitrary physical memory access**: the driver maps physical memory and exposes it to userland. The caller can map and modify any physical address.
- **Kernel function execution**: the driver exposes an IOCTL that calls a function pointer supplied by the caller.
- **Arbitrary process termination**: the driver exposes a capability to terminate any process by PID, including EDR agents, without checking the caller's privileges.

The [loldrivers.io](https://www.loldrivers.io) project maintains a catalog of known vulnerable drivers with documented vulnerability types, affected versions, and detection hashes. As of 2026, hundreds of drivers from hardware vendors, antivirus products, and system utilities appear in this catalog.

### Step 2 — Drop and Load the Vulnerable Driver

The attacker drops the vulnerable driver to disk (e.g. `RTCore64.sys`) and loads it:

```bat
sc create VulnDrv type= kernel binPath= C:\path\RTCore64.sys
sc start VulnDrv
```

Because the driver is legitimately signed, Windows loads it without error. The attacker now has a handle to a kernel driver with exploitable functionality.

### Step 3 — Exploit the Vulnerability

Using the driver's IOCTL interface, the attacker calls into the vulnerable driver from userland to perform kernel operations.

For a driver with arbitrary kernel write, the process looks roughly like:

```c
// Open handle to vulnerable driver
HANDLE hDrv = CreateFile("\\\\.\\RTCore64", ...);

// IOCTL parameters: write VALUE to KERNEL_ADDRESS
IOCTL_WRITE_MEMORY params;
params.address = target_kernel_address;
params.value   = new_value;

DeviceIoControl(hDrv, IOCTL_WRITE_MEMORY_CODE,
                &params, sizeof(params), ...);
```

Exactly what an attacker does with kernel write access depends on their goal. Common objectives:

- Disable DSE (Driver Signature Enforcement) by patching `g_CiEnabled` in `ci.dll` in kernel memory — allows loading unsigned drivers
- Kill EDR processes by zeroing their protection flags in `EPROCESS`
- Load an unsigned driver by writing it to kernel memory and calling its entry point via a corrupted function pointer

### Step 4 — Load Lethe

With DSE disabled via the kernel write primitive, the attacker loads `lethe.sys`:

```bat
sc create Lethe type= kernel binPath= C:\Lethe\lethe.sys
sc start Lethe
```

DSE is disabled. Windows loads the unsigned driver. Lethe's `DriverEntry` executes, the DPC engine arms, the hiding routines run.

### Step 5 — Cleanup

The attacker unloads the vulnerable driver to reduce the remaining footprint:

```bat
sc stop VulnDrv
sc delete VulnDrv
del C:\path\RTCore64.sys
```

Lethe remains running, hidden in kernel pool, polling for operator commands.

---

## Deploying Lethe via BYOVD

The BYOVD loader is not included in this repository. Writing one is straightforward for anyone familiar with Windows kernel development and the specific vulnerability in the chosen driver. What follows is the conceptual flow.

### Prerequisites

- Initial access to the target with sufficient privileges to load a kernel driver (typically `SeLoadDriverPrivilege`, which requires local administrator or SYSTEM)
- A suitable vulnerable driver (check loldrivers.io, verify not on Microsoft's blocklist)
- `lethe.sys` signed with a test certificate or prepared for unsigned loading

### Operational Flow

```
1. Achieve initial access
     ↓
2. Escalate to local admin / SYSTEM if needed
     ↓
3. Drop vulnerable driver to disk
     ↓
4. Load vulnerable driver via sc.exe or Service Control API
     ↓
5. Use BYOVD loader to exploit driver → disable DSE
     ↓
6. Drop lethe.sys to disk
     ↓
7. Load lethe.sys (DSE disabled — unsigned accepted)
     ↓
8. Lethe arms: DPC engine running, hiding complete
     ↓
9. Unload vulnerable driver, delete from disk
     ↓
10. Operator connects via client.exe over named pipe
     ↓
11. Execute: creddump, tokensteal, killedr
```

After step 9, the only footprint remaining is:
- `lethe.sys` on disk (at whatever path was registered)
- The `lethe.sys` registry service key (visible, not hidden)
- Lethe loaded in kernel memory (hidden from standard enumeration)

---

## Real-World BYOVD Usage

BYOVD is not a theoretical technique. It is in active use by threat actors ranging from ransomware operators to state-sponsored groups.

**Ransomware groups:**

<cite index="22-1">In March 2024, Akira was observed abusing the legitimate, signed Zemana anti-malware kernel driver `zamguard64.sys` to disable EDR at the kernel level.</cite> <cite index="22-1">In September 2024, a campaign used RealBlindingEDR to disable EDR drivers.</cite>

**APT groups:**

<cite index="24-1">Examples of malicious actors using the BYOVD technique include the Slingshot APT group, which implemented their main module, called Cahnadr, as a kernel-mode driver that can be loaded by vulnerable signed kernel drivers.</cite>

**Scale of the problem:**

<cite index="30-1">Research analyzing 8,779 malware samples found that they loaded 773 distinct signed drivers. The analysis flagged suspicious behavior in 48 drivers, and subsequent manual verification led to the responsible disclosure of seven previously unknown vulnerable drivers to Microsoft.</cite>

The technique works because the attacking driver is legitimately signed and trusted by Windows. The vulnerability lives inside a driver that the OS already loaded.

---

## Mitigations That Block BYOVD

### Microsoft Vulnerable Driver Blocklist

Microsoft maintains a blocklist of drivers with known vulnerabilities. On Windows 11 22H2 and later, this blocklist is enforced by default via WDAC (Windows Defender Application Control) policy. Blocked drivers cannot be loaded even if legitimately signed.

The blocklist is updated via Windows Update. Drivers added to the blocklist after an operator's chosen vulnerable driver was identified may suddenly be blocked mid-campaign. Operators must verify blocklist status before deployment.

The full current blocklist is available at:
`https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules`

### HVCI (Hypervisor-Protected Code Integrity)

HVCI is the strongest mitigation against BYOVD. Under HVCI, code integrity checks are performed inside a hypervisor-isolated environment. Even if a BYOVD attack disables DSE by patching kernel memory, the hypervisor-isolated integrity engine continues to enforce that only signed code executes. Patching `g_CiEnabled` in kernel memory does not affect the hypervisor's checks.

<cite index="35-1">HVCI enforces kernel-mode code integrity checks inside a hypervisor-isolated VTL1 environment, verifying driver and kernel code signatures before allowing execution, independent of the main kernel.</cite>

Under HVCI, a BYOVD attack can still perform kernel memory operations (read, write data) but cannot execute unsigned kernel code. Loading `lethe.sys` fails even with DSE patched.

### Smart App Control / WDAC

Windows Defender Application Control policies can block specific drivers by hash or by publisher certificate. Organizations with a restrictive WDAC policy can prevent known-vulnerable drivers from loading regardless of signature status.

---

## HVCI and Its Growing Reach

The operational relevance of Lethe and BYOVD techniques depends heavily on how widely HVCI is deployed. The picture is changing.

**Historical state (pre-2026):**
HVCI was enabled only on fresh Windows 11 installs and Secured-core PCs. Most enterprise Windows 10 machines and upgrade-path Windows 11 machines ran without it. BYOVD was broadly viable.

**Current state (October 2026):**
<cite index="35-1">Devices upgraded in place from Windows 10 to Windows 11 have historically lacked Memory Integrity because Microsoft only auto-enabled it on clean installs and Secured-core PCs. Starting with the October 2026 Windows Update, Microsoft is rolling HVCI enablement out to Windows 11 machines that pass a hardware and compatibility check.</cite>

<cite index="33-1">Machines that passed from Windows 10 to Windows 11 via upgrade, which remained without this protection, are now the target of Microsoft's auto-enablement rollout.</cite>

**Enterprise override:**
<cite index="33-1">In enterprise environments, if an administrator has enabled or disabled the feature via GPO, Intune, or the registry, Windows Update will not change that setting.</cite> Enterprise IT teams retain control and can disable HVCI where it conflicts with legacy drivers.

**Practical implication for Lethe:**

| Target Environment | HVCI Status | Lethe + BYOVD Viable |
|---|---|---|
| Windows 10 (any) | Generally OFF | Yes |
| Windows 11 (clean install, modern hardware) | Likely ON | No |
| Windows 11 (upgrade from Win10, pre-Oct 2026) | Generally OFF | Yes |
| Windows 11 (upgrade, post-Oct 2026 patch, eligible hardware) | Likely ON | No |
| Enterprise environment (GPO/Intune managed) | Admin-controlled | Depends |
| Secured-core PC | ON | No |
| OT/ICS environments | Generally OFF | Yes |
| Windows Server 2019/2022 | Generally OFF | Yes |

The window where BYOVD is broadly viable is narrowing. It remains viable on a large installed base of Windows 10 machines and unmanaged endpoints, but the trajectory is toward wider HVCI adoption.

---

## Honest Assessment of Operational Viability

**Where Lethe + BYOVD is viable today:**

- Windows 10 endpoints (large enterprise installed base, no HVCI)
- OT/ICS environments (typically run older Windows, minimal security controls)
- Windows Server deployments without VBS policy
- Mid-market organizations without enforced WDAC or HVCI policy
- Enterprise Windows 11 machines where IT has not applied HVCI

**Where it is not viable:**

- Any system with HVCI enabled
- Secured-core PCs
- Systems with Credential Guard enabled (limits token manipulation effectiveness)
- Systems with PPL (Protected Process Light) on lsass (limits LetheCredDump)
- Systems where the chosen vulnerable driver is on Microsoft's blocklist

**The honest summary:**

Lethe combined with BYOVD is a legitimate post-exploitation capability for a portion of real-world targets — the portion running without HVCI. That portion is large today. It is shrinking. The technique requires local admin access before BYOVD is even possible, meaning it operates after the initial foothold is established and escalated.

Lethe as published is a research and lab tool. Using it in a production engagement requires a BYOVD loader (not included), operational awareness of the target's HVCI and blocklist status, and the judgment to apply it where the conditions are right.

---

## References

- [MITRE ATT&CK T1068 — Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)
- [loldrivers.io — Vulnerable Driver Database](https://www.loldrivers.io)
- [Microsoft Recommended Driver Block Rules](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules)
- [Exploring Vulnerable Windows Drivers — Cisco Talos, 2024](https://blog.talosintelligence.com/exploring-vulnerable-windows-drivers/)
- [Breaking Boundaries: Vulnerable Drivers — Check Point Research, 2024](https://research.checkpoint.com/2024/breaking-boundaries-investigating-vulnerable-drivers-and-mitigating-risks/)
- [ESET Research: BYOVD](https://www.eset.com/int/about/newsroom/press-releases/research/esets-research-into-bring-your-own-vulnerable-driver-details-attacks-on-drivers-in-windows-core/)
- [Unveiling BYOVD Threats — NDSS Symposium](https://www.ndss-symposium.org/ndss-paper/unveiling-byovd-threats-malwares-use-and-abuse-of-kernel-drivers/)
- [BYOVD — Quarkslab Series, 2025](https://blog.quarkslab.com/tag/windows.html)
- [VBS and HVCI — Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/?p=92539)
- [Windows 11 Memory Integrity Auto-Enable, October 2026](https://anavem.com/explanations/windows-11-memory-integrity-microsoft-enables-hvci-by-default-in-october-2026)

---

<div align="center">

*Λήθη — river of oblivion*

---

Built by [0x3xp](https://0x3xp.github.io)

[![X](https://img.shields.io/badge/X-0xmrlowlwvel-000000?style=flat&logo=x&logoColor=white)](https://x.com/0xmrlowlwvel)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-piyushaakash-0A66C2?style=flat&logo=linkedin&logoColor=white)](https://linkedin.com/in/piyushaakash)
[![YouTube](https://img.shields.io/badge/YouTube-infoseclk-FF0000?style=flat&logo=youtube&logoColor=white)](https://youtube.com/@infoseclk)

</div>
