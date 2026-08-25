# Incident Report: LLMNR Poisoning, Credential Submission, and Suspected Remote Service Activity

**Classification:** Simulated incident in an authorized, isolated home lab

**Environment:** `jtwyman.test` Active Directory domain (single DC), VirtualBox internal network

**Analyst:** Jason Twyman

**Exercise date shown in artifacts:** 2026-08-20

**Identifier note:** All visible host, user, domain, and poisoned-host labels are synthetic lab identifiers. They do not identify production systems, domains, or accounts.

---

## 1. Executive Summary

This lab exercised a multi-stage intrusion scenario against `DC01` (`10.10.10.10`) from the authorized attacker VM `10.10.10.20`. Screenshots directly show Nmap reconnaissance, an attempted Responder listener, a browser at the synthetic hostname, a Windows Security prompt, and a later NetNTLMv2 challenge-response capture. Operator notes attribute the browser redirection to Responder answering a poisoned name-resolution request, but no raw Responder log or PCAP independently verifies that causal step. The notes also state that the domain Administrator credential was manually entered and submitted in the prompt; the prompt screenshot shows a redacted username field and an empty password field, so it does not independently prove entry or submission. The captured challenge-response was tested offline in the lab, and the recovered lab credential was subsequently used with Impacket remote-administration tooling.

The evidence currently in this repository supports these conclusions:

1. **Reconnaissance occurred.** Nmap output is visible in screenshots.
2. **The capture path required user action according to operator notes.** The notes attribute redirection to LLMNR poisoning and the capture to manual submission at an untrusted NTLM-over-HTTP prompt; the current screenshots do not independently prove either the poisoning/redirection or the password entry/submission.
3. **A NetNTLMv2 challenge-response was captured and tested offline.** The sensitive response and recovered plaintext are redacted.
4. **Privileged network authentication is reported but not yet independently verified.** The lab notes/transcribed Windows Security Event 4624, Logon Type 3, report `Administrator` authenticating from `10.10.10.20`; the raw event export is pending.
5. **Remote service execution remains suspected, not target-confirmed.** Attacker-side Impacket/PsExec output reports share access and Service Control Manager operations, but target-side service-installation and process-creation records have not been exported.

**Impact assessment:** In a production environment, reported disclosure and reuse of a privileged domain credential against a domain controller warrants critical handling. The lab notes and transcribed Event 4624 report privileged network authentication, pending verification against the raw event export. The present repository does not independently confirm that authentication, process execution, or persistence on the target.

**Root cause and contributing conditions:** This was not caused by LLMNR alone. According to operator notes, the HTTP chain required (a) legacy/fallback name resolution that could be poisoned, (b) NTLM authentication over HTTP to an untrusted destination, (c) manual submission of credentials at the browser prompt, (d) use of a highly privileged account, and (e) a lab password recoverable with the prepared wordlist. The earlier SMB path produced no captured credential material, but the available artifacts do not determine why. Nmap independently reported SMB signing enabled and required on DC01 in its SMB-server role. Requiring server signing mitigates relay to that SMB server; it does not establish the target's outbound/client signing behavior and must not be presented as the cause of the failed capture.

---

## 2. Timeline and Clock Caveat

The artifacts display mixed 12-hour and 24-hour timestamps. The recon screenshots/notes show `22:49–22:50`, while later screenshots and transcribed records show `12:35–12:57 PM`, all labeled 2026-08-20. Those values cannot establish a single same-day chronology without timezone, clock-offset, reboot, and source-clock validation. They are preserved below **as displayed**, not normalized or silently reordered. The stage order comes from the documented lab procedure and screenshots, not from a proven cross-source timestamp correlation.

| Displayed time | Observed or transcribed event | Provenance / limitation |
|---|---|---|
| `22:49:48` | Nmap-related Suricata signature | Transcribed; raw `fast.log`/`eve.json` pending export |
| `22:50:51` | Malformed SMB dialect signature during failed SMB path | Transcribed; raw Suricata export pending |
| `12:35–12:53 PM` | NTLM-over-HTTP-related signatures | Transcribed summary; raw Suricata export pending |
| `12:47:58 PM` | Responder reports HTTP NetNTLMv2 challenge-response capture for `JTWYMAN\Administrator` | Screenshot; response redacted; raw Responder log pending |
| `12:53 PM` | John reports successful offline recovery against the prepared wordlist | Screenshot; plaintext redacted |
| `12:53:53 PM` | `ET INFO Suspected Impacket WMIExec Activity` | Transcribed; signature is not proof of a specific Impacket script or target execution |
| `12:57:36 PM` | Security Event 4624, Logon Type 3, `Administrator`, source `10.10.10.20` | Transcribed endpoint event; raw `.evtx` pending |

**Next timestamp validation:** export raw records with timezone/UTC fields, record VM clock settings and reboot boundaries, and normalize into UTC while retaining each source timestamp.

---

## 3. Detection Assessment

The report notes the following Suricata signatures from the lab notes:

- `ET SCAN Possible Nmap User-Agent Observed`
- `SURICATA SMB malformed request dialects`
- `SURICATA HTTP Request unrecognized authorization method`
- `SURICATA HTTP Response excessive header repetition`
- `ET INFO NTLM Session Setup Request - Negotiate`
- `ET INFO NTLMv1 Session Setup Response - Challenge`
- `ET INFO NTLM Session Setup Request - Auth`
- `[1:2043996:1] ET INFO Suspected Impacket WMIExec Activity`

These strings are useful investigation leads, but the repository currently contains neither `fast.log` nor `eve.json`; exact alert counts, packet fields, ordering, and correlation are therefore pending verification. The rule name `Suspected Impacket WMIExec Activity` should not be treated as proof that `wmiexec` ran. Tool-family signatures can match shared SMB/DCERPC behavior.

A reasonable triage hypothesis is that reconnaissance, repeated NTLM-over-HTTP observations, and an Impacket-family signature from the same lab source are related. Confirming that hypothesis requires the raw alert records and packet/flow identifiers.

---

## 4. Investigation Narrative

### 4.1 Reconnaissance

Nmap screenshots show scanning against DC01 and report SMB signing as enabled and required. This is direct attacker-console evidence of reconnaissance and configuration discovery in the isolated lab.

### 4.2 Name-Resolution Poisoning and Manual Credential Submission

The screenshots show a Responder launch attempt on the attacker VM followed by socket/network-unreachable errors. The failed SMB path produced poisoned-name-resolution responses according to the notes, but no captured credential material. The cause remains undetermined because no PCAP or raw Responder session log is available. Separately, Nmap reported that DC01 required signing while acting as an SMB server. That server-side setting mitigates relay to DC01; it neither proves why a fake-SMB capture failed nor establishes DC01's signing behavior for outbound SMB when acting as a client.

The successful lab path used Responder's HTTP listener. A browser on DC01 navigated to a poisoned hostname and displayed a Windows Security credential prompt. The operator notes state that the domain Administrator credential was **manually entered and submitted**. [`08_dc01_username_redacted_password_not_shown.png`](evidence/screenshots/08_dc01_username_redacted_password_not_shown.png) shows a redacted username field and an empty password field; it does not independently demonstrate password entry or submission. After the noted action, Responder reported:

```text
[HTTP] NetNTLMv2 Client             : 10.10.10.10
[HTTP] NetNTLMv2 Username           : JTWYMAN\Administrator
[HTTP] NetNTLMv2 Challenge-Response : [REDACTED]
```

The resulting material is a **NetNTLMv2 challenge-response**, not the account's NT password hash and not a plaintext password. It can be tested offline against password candidates; whether it can be relayed depends on protocol and target protections and was not demonstrated here.

### 4.3 Offline Credential Recovery

John the Ripper was run with its `netntlmv2` input format against a small, purpose-built lab wordlist. The screenshot reports one recovered credential; the plaintext and wordlist values are redacted. The fast result demonstrates that the known lab password appeared in the prepared candidate set. It does not support a general claim about cracking speed or real-world password strength.

### 4.4 Credential Reuse and Suspected Remote Service Activity

The recovered lab credential was used first with an Impacket WMIExec-style client, which appeared to hang and was abandoned. It was then used with Impacket PsExec-style tooling. Credential-bearing command lines are intentionally omitted.

Attacker-side output reports:

```text
[*] Requesting shares on 10.10.10.10
[*] Found writable share ADMIN$
[*] Uploading file [LAB-GENERATED-NAME].exe
[*] Opening SVCManager on 10.10.10.10
[*] Creating service [LAB-GENERATED-NAME]
[*] Starting service [LAB-GENERATED-NAME]
```

This is evidence only of client-reported service operations and is consistent with an attempted remote service workflow. It is **not independent target-side proof** that the upload completed, the service was installed or started, or a process executed. Screenshots [`17_impacket_psexec_client_reported_service_operations.png`](evidence/screenshots/17_impacket_psexec_client_reported_service_operations.png) and [`18_impacket_psexec_no_shell_confirmation.png`](evidence/screenshots/18_impacket_psexec_no_shell_confirmation.png) show the same client-reported sequence ending at `Starting service`; neither shows a command prompt, command output, or other confirmation of an interactive remote shell.

### 4.5 Endpoint Authentication Evidence

The lab notes transcribe a DC01 Windows Security event with:

- **Event ID:** 4624 (successful logon)
- **Logon Type:** 3 (network)
- **Account:** `Administrator`
- **Source Network Address:** `10.10.10.20`
- **Displayed time:** `12:57:36 PM`

The lab notes/transcribed event report successful network authentication from the attacker VM using the privileged account. That claim remains pending verification against the raw event export. Even when verified, Event 4624 Logon Type 3 does **not** by itself establish remote code execution, service creation, process creation, or an interactive shell.

Target-side validation sought for execution includes Security Event 4697, System Event 7045, Security Event 4688, relevant Sysmon process/service/network events, service-registry changes, and the uploaded binary's file metadata/hash.

---

## 5. Severity and Response

**Severity recommendation: Critical in a production analogue.** The screenshots support capture and offline recovery of privileged credential material, while the lab notes/transcribed Event 4624 report successful network authentication to a domain controller pending raw-export verification. Even with authentication awaiting independent verification and execution unconfirmed, the reported access path justifies immediate containment.

**Immediate actions:**

1. Disable or reset the affected privileged credential and review all use of it.
2. Isolate the source host and preserve volatile and disk evidence.
3. Export Security, System, and Sysmon logs before retention windows roll over.
4. Search for new services, binaries in administrative-share destinations, scheduled tasks, and other persistence.
5. Preserve Suricata `eve.json`/`fast.log`, Responder logs, and a scoped PCAP if collection is still possible.

**Hardening:**

- Disable LLMNR and NBT-NS where operationally feasible.
- Restrict or disable NTLM, especially NTLM over HTTP; prefer Kerberos and enforce Extended Protection for Authentication where supported.
- Train users not to enter credentials into unexpected prompts and configure browser/intranet authentication policy narrowly.
- Use separate, least-privilege administrative accounts; do not browse as a domain administrator.
- Maintain SMB signing and segment access to domain controllers.
- Correlate name-resolution poisoning, NTLM-over-HTTP, privileged logon, service installation, and process creation telemetry.

---

## 6. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence status |
|---|---|---|---|
| Reconnaissance | Active Scanning | T1595 | Nmap screenshot |
| Credential Access | Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay (name-resolution-poisoning portion only) | T1557.001 | Operator notes attribute redirection to name-resolution poisoning; packet-level or raw-log verification is unavailable. The manual HTTP prompt/submission is separate causal context from operator notes, not part of the technique mapping. |
| Credential Access | Brute Force: Password Cracking | T1110.002 | John screenshot; sensitive result redacted |
| Lateral Movement | Remote Services: SMB/Windows Admin Shares | T1021.002 | Attacker-side PsExec-style output; target confirmation pending |
| Execution | System Services: Service Execution | T1569.002 | **Hypothesis only** until target service/process evidence is collected |

---

## 7. Evidence Index and Gaps

| Evidence | Repository status | What it proves / does not prove |
|---|---|---|
| [Screenshots 01–18 and manifest](evidence/screenshots/README.md) | Included as sanitized derivatives; sensitive fields redacted | Lab workflow and attacker-side observations within the per-image limitations; not a substitute for raw logs |
| Packet capture | **Pending / not included** | No claim of packet-level verification can be made from this repository |
| Suricata `fast.log` / `eve.json` | **Pending / not included** | Alert text is transcribed; counts, timestamps, and flow correlation remain unverified |
| Responder raw session log | **Pending / not included** | Screenshot supports capture; original log provenance remains to be preserved |
| Windows Security/System/Sysmon exports | **Pending / not included** | Event 4624 is transcribed; execution/service evidence remains unverified |
| NetNTLMv2 challenge-response and plaintext | Intentionally redacted | Sensitive material is not distributed in the portfolio |

### Next validation steps

1. Export the raw Suricata records and identify exact event/flow IDs for each stage.
2. Export a sanitized PCAP or document that packet evidence was not retained; do not reconstruct one.
3. Export the original Event 4624 and verify its Logon ID, authentication package, workstation/source fields, UTC time, and neighboring events.
4. Search/export Events 4697, 7045, and 4688 plus relevant Sysmon records for the reported service/binary names and time window.
5. Confirm whether the uploaded binary existed, whether a service started, what process tree resulted, and whether cleanup succeeded.
6. Record source time zones, VM clock offsets, and reboot periods; build a normalized UTC timeline only from those values.
7. Hash and preserve exported evidence, document acquisition steps, and keep unsanitized originals outside the public repository.

---

## 8. Conclusion

The lab demonstrates a plausible credential-compromise chain but also shows why precise evidence language matters. Operator notes attribute redirection to LLMNR poisoning, but the repository lacks the PCAP or raw Responder log needed to verify that step independently. The screenshots support an NTLM-over-HTTP challenge-response exchange; operator notes attribute the capture to manual submission of a privileged credential; and the prepared wordlist enabled offline recovery. The lab notes/transcribed Event 4624 report that the credential then produced a successful network authentication, but the raw event export is still required to verify that claim. Attacker-side PsExec-style output suggests remote service operations, but target-side service and process evidence is still required before claiming remote code execution.
