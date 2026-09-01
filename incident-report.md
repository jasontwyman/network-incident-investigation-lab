# Incident Report: Reported Fallback Name-Resolution Poisoning, Credential Submission, and Suspected Remote Service Activity

**Classification:** Simulated incident in an authorized, isolated home lab

**Environment:** `jtwyman.test` Active Directory domain (single DC), VirtualBox internal network

**Analyst:** Jason Twyman

**Exercise date shown in artifacts:** 2026-08-20

**Identifier note:** All visible host, user, domain, and poisoned-host labels are synthetic lab identifiers. They do not identify production systems, domains, or accounts.

---

## 1. Executive Summary

This lab exercised a multi-stage intrusion scenario against `DC01` (`10.10.10.10`) from the authorized attacker VM `10.10.10.20`. Screenshots directly show Nmap reconnaissance, an attempted Responder listener, a browser at the synthetic hostname, a Windows Security prompt, and later Responder HTTP NetNTLMv2 client/username output with the challenge-response region redacted. Operator notes attribute the browser redirection to Responder answering a poisoned LLMNR request, but no raw Responder log or PCAP independently verifies poisoning or distinguishes LLMNR from NBT-NS, DNS, or another resolution path. The notes also state that the domain Administrator credential was manually entered and submitted in the prompt; the prompt screenshot shows a redacted username field and an empty password field, so it does not independently prove entry or submission. Operator notes state that the challenge-response was recovered offline and that the recovered lab credential was subsequently used with Impacket remote-administration tooling; the public John screenshot shows one NetNTLMv2 input loaded but redacts all result lines.

The evidence currently in this repository supports these conclusions:

1. **Reconnaissance occurred.** Nmap output is visible in screenshots.
2. **The capture path required user action according to operator notes.** The notes attribute redirection to LLMNR poisoning and the capture to manual submission at an untrusted NTLM-over-HTTP prompt; the current screenshots do not independently prove either the poisoning/redirection or the password entry/submission.
3. **Responder and John activity is partially evidenced.** Responder visibly reports an HTTP NetNTLMv2 client and username, and John visibly loads one NetNTLMv2 input. The challenge-response and all John result lines are redacted; capture of the exact material and successful recovery remain supported by operator notes rather than independently verifiable public evidence.
4. **Privileged network authentication is reported but not yet independently verified.** The lab notes/transcribed Windows Security Event 4624, Logon Type 3, report `Administrator` authenticating from `10.10.10.20`; the raw event export is pending.
5. **Remote service execution remains suspected, not target-confirmed.** Attacker-side Impacket/PsExec output reports share access and Service Control Manager operations, but target-side service-installation and process-creation records have not been exported.

**Impact assessment:** In a production environment, reported disclosure and reuse of a privileged domain credential against a domain controller warrants urgent containment and potentially critical handling. The lab notes and transcribed Event 4624 report privileged network authentication, pending verification against the raw event export. The present repository does not independently confirm successful password recovery, credential reuse, target authentication, process execution, or persistence.

**Root cause and contributing conditions:** This was not caused by a fallback name-resolution protocol alone. According to operator notes, the HTTP chain required (a) fallback name resolution that could be poisoned, (b) NTLM authentication over HTTP to an untrusted destination, (c) manual submission of credentials at the browser prompt, (d) use of a highly privileged account, and (e) a lab password present in the prepared wordlist. The evidence does not identify LLMNR versus NBT-NS or another lookup path. The earlier SMB path produced no captured credential material, but the available artifacts do not determine why. Nmap independently reported SMB signing enabled and required on DC01 in its SMB-server role. Requiring server signing mitigates relay to that SMB server; it does not establish the target's outbound/client signing behavior and must not be presented as the cause of the failed capture.

---

## 2. Timeline and Clock Caveat

The artifacts display mixed 12-hour and 24-hour timestamps. The recon screenshots/notes show `22:49–22:50`, while later screenshots and transcribed records show `12:35–12:57 PM`, all labeled 2026-08-20. Those values cannot establish a single same-day chronology without timezone, clock-offset, reboot, and source-clock validation. They are preserved below **as displayed**, not normalized or silently reordered. The stage order comes from the documented lab procedure and screenshots, not from a proven cross-source timestamp correlation.

| Displayed time | Observed or transcribed event | Provenance / limitation |
|---|---|---|
| `22:49:48` | Nmap-related Suricata signature | Transcribed; raw `fast.log`/`eve.json` pending export |
| `22:50:51` | Malformed SMB dialect signature during failed SMB path | Transcribed; raw Suricata export pending |
| `12:35–12:53 PM` | NTLM-over-HTTP-related signatures | Transcribed summary; raw Suricata export pending |
| `12:47:58 PM` | Responder visibly reports HTTP activity plus a NetNTLMv2 client/username for `JTWYMAN\Administrator`; operator notes report challenge-response capture | Response region redacted; raw Responder log pending |
| `12:53 PM` | Operator notes report successful offline recovery against the prepared wordlist | Screenshot visibly proves only that John loaded one NetNTLMv2 input; all result lines are redacted |
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

These strings are useful investigation leads, but the repository currently contains neither `fast.log` nor `eve.json`; exact alert counts, packet fields, ordering, and correlation are therefore pending verification. The transcribed rule name `NTLMv1 Session Setup Response - Challenge` does not by itself establish the negotiated NTLM response version or contradict Responder's separate NetNTLMv2 label; that determination requires the raw alert/packet fields. Likewise, `Suspected Impacket WMIExec Activity` should not be treated as proof that `wmiexec` ran. Tool-family signatures can match shared SMB/DCERPC behavior.

A reasonable triage hypothesis is that reconnaissance, repeated NTLM-over-HTTP observations, and an Impacket-family signature from the same lab source are related. Confirming that hypothesis requires the raw alert records and packet/flow identifiers.

---

## 4. Investigation Narrative

### 4.1 Reconnaissance

Nmap screenshots show scanning against DC01 and report SMB signing as enabled and required. This is direct attacker-console evidence of reconnaissance and configuration discovery in the isolated lab.

### 4.2 Reported Name-Resolution Poisoning and Manual Credential Submission

The screenshots show a Responder launch attempt on the attacker VM followed by socket/network-unreachable errors. The failed SMB path produced poisoned-name-resolution responses according to the notes, but no captured credential material. The cause remains undetermined because no PCAP or raw Responder session log is available. Separately, Nmap reported that DC01 required signing while acting as an SMB server. That server-side setting mitigates relay to DC01; it neither proves why a fake-SMB capture failed nor establishes DC01's signing behavior for outbound SMB when acting as a client.

According to operator notes, the working lab path used Responder's HTTP listener and name-resolution poisoning; the repository cannot establish whether LLMNR, NBT-NS, DNS, or another lookup path supplied the destination. A browser on DC01 displayed the synthetic hostname and a Windows Security credential prompt. The operator notes state that the domain Administrator credential was **manually entered and submitted**. [`08_dc01_username_redacted_password_not_shown.png`](evidence/screenshots/08_dc01_username_redacted_password_not_shown.png) shows a redacted username field and an empty password field; it does not independently demonstrate password entry or submission. After the noted action, the notes transcribe the following Responder output; the public screenshot retains the client and username lines while the response region is redacted:

```text
[HTTP] NetNTLMv2 Client             : 10.10.10.10
[HTTP] NetNTLMv2 Username           : JTWYMAN\Administrator
[HTTP] NetNTLMv2 Challenge-Response : [REDACTED]
```

The resulting material is a **NetNTLMv2 challenge-response**, not the account's NT password hash and not a plaintext password. It can be tested offline against password candidates; whether it can be relayed depends on protocol and target protections and was not demonstrated here.

### 4.3 Offline Credential Recovery

John the Ripper was run with its `netntlmv2` input format against a small, purpose-built lab wordlist. The public screenshot visibly shows one NetNTLMv2 input loaded, but all result/status lines, plaintext, and candidate values are redacted. Operator notes report one successful recovery and state that the known lab password appeared in the prepared candidate set; that result is not independently verifiable from the derivative and does not support a general claim about cracking speed or real-world password strength.

### 4.4 Credential Reuse and Suspected Remote Service Activity

Operator notes state that the recovered lab credential was used first with an Impacket WMIExec-style client, which appeared to hang and was abandoned, and then with Impacket PsExec-style tooling. The redacted screenshots do not independently identify either invocation or expose the credential-bearing command lines; the later client-reported service workflow is consistent with PsExec-style behavior.

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

**Severity recommendation: High based on the public evidence; Critical if privileged credential recovery/reuse is verified.** The screenshots support an HTTP NetNTLMv2 exchange and one offline input load, while successful recovery, target authentication, and remote service activity depend partly on operator notes, redacted client output, and a transcribed Event 4624 pending raw-export verification. The reported access path still justifies immediate containment in a production analogue.

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
| Credential Access | Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay (name-resolution-poisoning portion only) | T1557.001 | Operator notes attribute redirection to poisoning, but the repository cannot distinguish LLMNR, NBT-NS, DNS, or another resolution path; packet-level or raw-log verification is unavailable. The manual HTTP prompt/submission is separate causal context from operator notes, not part of the technique mapping. |
| Credential Access | Brute Force: Password Cracking | T1110.002 | John command and one loaded NetNTLMv2 input are visible; successful recovery is operator-noted because all result lines are redacted |
| Lateral Movement | Remote Services: SMB/Windows Admin Shares | T1021.002 | Attacker-side service-workflow output is consistent with PsExec-style behavior; tool identity and target confirmation are pending |
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

The lab demonstrates a plausible credential-compromise chain but also shows why precise evidence language matters. Operator notes attribute redirection to LLMNR poisoning, but the repository lacks the PCAP or raw Responder log needed to verify poisoning or distinguish LLMNR from NBT-NS, DNS, or another resolution path. The screenshots support an NTLM-over-HTTP exchange and show John loading one NetNTLMv2 input; operator notes attribute the exchange to manual submission of a privileged credential and report successful offline recovery. The lab notes/transcribed Event 4624 then report successful network authentication, but the raw event export is still required to verify that claim. Attacker-side output is consistent with PsExec-style remote service operations, but the invocation is redacted and target-side service/process evidence is still required before claiming remote code execution.
