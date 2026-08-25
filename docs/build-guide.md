# Build Guide: Network Incident Investigation Lab

This guide documents an **authorized exercise in an isolated VirtualBox internal network**. Do not run poisoning, credential-capture, cracking, or remote-administration tooling on systems or networks you do not own or have explicit permission to test. Sensitive values and credential-bearing invocations are intentionally omitted.

All host, user, domain, and poisoned-host labels visible in the screenshots are synthetic lab identifiers, not production identifiers.

## Prerequisites

- VirtualBox with two VMs on `intnet` only (no bridged adapter):
  - `DC01` — Windows Server 2025 domain controller for `jtwyman.test`, `10.10.10.10/24`.
  - `kali` — authorized lab attacker, `10.10.10.20/24` on `eth1`.
- Suricata and Sysmon configured on DC01.
- A lab-only account/password that is not reused anywhere else.
- A collection plan for PCAP, Suricata logs, Responder logs, and Windows event exports.

## Part 1 — Sensor Notes

### Sysmon and Npcap

Install Sysmon for process/network telemetry and Npcap for packet capture. GUI installers launched through WinRM may appear in Session 0 rather than the interactive console. In this lab, an interactive scheduled task was used to launch the Npcap installer.

### Suricata on Windows

Suricata 8.0.6 was configured with ET Open rules. The manually downloaded rule bundle required its configured filenames to match the extracted files. Rules requiring unavailable `libmagic` support were disabled. When editing rule files in Windows PowerShell 5.1, write UTF-8 without a byte-order mark.

Use the Npcap device path rather than a friendly adapter name:

```powershell
$guid = (Get-NetAdapter -Name "Internal").InterfaceGuid
$iface = "\Device\NPF_$guid"
```

In this environment, running Suricata from a scheduled task was more reliable than a process started inside a WinRM session. Verify collection by checking Suricata statistics and generating benign test traffic before the exercise.

**Collection requirement:** copy `eve.json`, `fast.log`, configuration/rule versions, and a scoped PCAP to an evidence location after the run. Those raw exports were not retained for the portfolio version of this exercise and remain pending.

## Part 2 — Authorized Attacker VM

Confirm Responder, John the Ripper, hashcat, Impacket, and Nmap are installed. Verify that the attacker interface is attached only to the isolated lab network.

## Part 3 — Exercise Procedure

### 3.1 Reconnaissance

A lab-authorized Nmap scan was run against `10.10.10.10`. The screenshots show OS/service discovery and SMB signing reported as enabled and required.

### 3.2 Responder

Responder was attempted on `eth1`. Screenshot 03 shows the launch command returning to the shell, while screenshot 04 shows socket/network-unreachable errors; neither proves a healthy long-running listener. A raw Responder session log would be required for stronger process and capture provenance, but no such log is included.

### 3.3 Failed SMB capture path

According to operator notes, requests to a nonexistent hostname triggered fallback name resolution
and Responder answered, but no NetNTLMv2 challenge-response was captured through the SMB path.
The available artifacts do not independently verify that poisoning/response step or establish why
the capture failed: no PCAP or raw Responder session log was retained. Independently, Nmap
reported SMB signing enabled and required while DC01 was acting as an SMB server. Requiring
signing mitigates relay to that server; it does not by itself prevent a client from sending an NTLM
challenge-response to a listener, establish DC01's outbound/client signing policy, or prove that
signing caused this capture failure. Inbound server requirements and outbound client behavior must
be assessed separately.

### 3.4 HTTP path and required user action

The working lab path used Responder's HTTP listener. A browser on the DC01 console navigated to the synthetic hostname. Edge displayed a native Windows Security prompt rather than silently authenticating. Operator notes attribute the redirection to name-resolution poisoning; without the raw Responder log or PCAP, the repository does not independently verify that causal step.

According to the operator notes, a lab user then **manually entered and submitted the domain Administrator credential**. [`08_dc01_username_redacted_password_not_shown.png`](../evidence/screenshots/08_dc01_username_redacted_password_not_shown.png) shows the prompt with the username field redacted and the password field empty; it does not prove password entry or submission. The notes attribute browser redirection to LLMNR poisoning, but the repository does not independently verify that step and poisoning alone would not disclose the credential. The reported contributing chain was:

1. fallback name resolution could be poisoned;
2. the destination offered NTLM over HTTP;
3. the browser displayed an unexpected credential prompt;
4. operator notes state that the user manually submitted a privileged credential; and
5. the lab password was present in a prepared candidate list.

Responder subsequently recorded:

```text
[HTTP] NetNTLMv2 Client             : 10.10.10.10
[HTTP] NetNTLMv2 Username           : JTWYMAN\Administrator
[HTTP] NetNTLMv2 Challenge-Response : [REDACTED]
```

This is a **NetNTLMv2 challenge-response**, not an NT password hash or a plaintext password. The unsanitized response must remain outside the public repository.

### 3.5 Offline test

John the Ripper's `netntlmv2` input format was used against a small, prepared lab wordlist. The exact response, candidate list, recovered plaintext, and commands containing sensitive file content are omitted. The screenshot retains nonsecret proof that John loaded one NetNTLMv2 input and completed the run; the result is redacted.

Hashcat was attempted first, but the VM lacked a usable OpenCL runtime. The screenshot preserves that troubleshooting context after redaction.

### 3.6 Credential reuse and remote-service hypothesis

An Impacket WMIExec-style attempt appeared to hang and was abandoned. An Impacket PsExec-style attempt then reported share access, file upload, and Service Control Manager operations. **Credential-bearing command lines are intentionally omitted.**

The attacker-side output is consistent with attempted service creation/start, but is not sufficient target-side confirmation. The lab notes/transcribed Event 4624 Logon Type 3 report successful network authentication, pending verification against the raw event export. Even if verified, do not use that event as proof of remote code execution.

Collect the following before claiming service execution:

```powershell
$start = [datetimeoffset]'2026-08-20T12:30:00-07:00'
$end   = [datetimeoffset]'2026-08-20T13:10:00-07:00'
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4688,4697; StartTime=$start; EndTime=$end}
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045; StartTime=$start; EndTime=$end}
```

Replace the example offset and bounds with values derived from verified VM clock/timezone records; do not assume the displayed times are already correlated. Export the scoped source logs as EVTX (for example, with `wevtutil epl` plus a bounded XPath query), compute SHA-256 hashes immediately after export, and record the query, acquisition time, host, timezone, and tool version. Also export relevant Sysmon events, service registry state, and file metadata/hash for any reported uploaded binary. Correlate records using Logon ID, process IDs, source address, and verified UTC timestamps.

### 3.7 Review Suricata

Review Nmap-, NTLM-, HTTP-, SMB/DCERPC-, and Impacket-related events in raw `eve.json`/`fast.log`. A rule name such as `Suspected Impacket WMIExec Activity` is a detection lead, not proof that a specific script ran. Preserve the raw records needed to verify signature IDs, flow IDs, addresses, ports, and timing.

## Evidence Handling and Known Gaps

The portfolio currently includes sanitized screenshots only. The following remain pending and must not be described as included packet/endpoint proof:

- PCAP;
- raw Suricata `eve.json` and `fast.log`;
- raw Responder session log;
- Windows Security/System `.evtx` exports;
- Sysmon export;
- target-side service/process/file confirmation.

Artifact clocks show mixed `22:xx` and `12:xx PM` values on the same displayed date. Do not invent a correction. Record each VM's timezone, offset, reboot boundaries, and UTC fields before producing a normalized timeline.

Store unsanitized evidence outside the public repository, hash preserved exports, document acquisition steps, and publish only reviewed/redacted derivatives.

## Operational Lessons

- Keep the attack and target VMs isolated from production and home networks.
- Do not browse or perform routine user activity as a domain administrator.
- An unexpected authentication prompt is a meaningful control point; operator notes state that user submission was required here.
- SMB signing is a relay mitigation. Nmap's server-side result did not explain the failed SMB capture path and did not describe DC01's outbound/client behavior; the HTTP path was separate.
- Validate every tool-side success message with independent target telemetry.
- Recheck interface addresses and collection health after VM reboots.
- Preserve raw evidence before restarting services or cleaning up the lab.
