# Network Incident Investigation Lab

A hands-on incident-response exercise conducted in an **authorized, isolated VirtualBox lab**.
The project follows an Active Directory attack narrative from reconnaissance and NTLM
authentication activity through attempted remote administration, then converts the available
artifacts into a structured incident report with containment and validation recommendations.

The completed portfolio package includes an incident report, an 18-image sanitized evidence
manifest, MITRE-relevant investigation context, and explicit separation between observations,
analyst interpretation, attacker-side output, and target-side confirmation.

## What this repository demonstrates

The lab procedure covered:

**Nmap reconnaissance → operator-noted Responder/fallback-name-resolution path → operator-noted manual credential submission to an attacker-controlled HTTP authentication prompt → Responder output associated with a redacted NetNTLMv2 challenge-response → operator-noted offline password recovery in the lab → attempted remote administration with Impacket tooling.**

The available artifacts support different confidence levels. All visible host, user, and domain names—including `DC01`, `kali`, `mowgli0242`, `JTWYMAN`, `Administrator`, `jtwyman.test`, and the poisoned host label—are synthetic identifiers used only in the isolated lab; they do not identify production systems or accounts.

- Responder screenshots show the attempted listener and later HTTP NetNTLMv2 client/username output, with the challenge-response region redacted. Operator notes attribute redirection to LLMNR poisoning, but no raw log or PCAP independently verifies poisoning or establishes whether LLMNR, NBT-NS, DNS, or another resolution path supplied the destination.
- Attacker-console screenshots show an Impacket PsExec-style client requesting shares and reporting service-manager actions.
- Lab notes and a transcribed Windows Security Event 4624, Logon Type 3, report successful network authentication from the lab attacker IP, pending verification against the raw event export; even a verified Event 4624 would **not** by itself prove remote code execution.
- Target-side service-installation and process-creation evidence (for example, Events 4697/7045/4688 or relevant Sysmon records) has not yet been exported and remains a validation gap.
- PCAPs, Suricata `eve.json`/`fast.log`, the raw Responder session log, and Windows Security/System/Sysmon EVTX exports are not included in this repository and are explicitly marked pending.
- The failed SMB path produced no captured credential material. Its cause is undetermined. Nmap separately reported that DC01 required SMB signing when acting as an SMB server; that observation is a relay-mitigation finding, not proof that signing caused the capture failure or that the same requirement applied when DC01 acted as an SMB client.

The centerpiece deliverable is [`incident-report.md`](incident-report.md), which separates observations, interpretation, and unverified claims.

## Environment

| Host | Role | Notes |
|---|---|---|
| `DC01` | Lab target — domain controller, `jtwyman.test` (`10.10.10.10`) | Windows Server 2025; Suricata and Sysmon configured for telemetry |
| `kali` | Authorized lab attacker (`10.10.10.20`) | Responder, Impacket, John the Ripper, Nmap |

Both VMs used the VirtualBox internal network `intnet`; no bridged interface was used for the exercise traffic.

## Repository structure

```text
├── README.md
├── incident-report.md
├── docs/
│   └── build-guide.md
└── evidence/
    ├── screenshots/             # 18 reviewed screenshots plus evidence manifest
    ├── pcaps/                   # placeholder; exports pending
    └── suricata-alerts/         # placeholder; raw exports pending
```

## Key skills demonstrated

- Correctly distinguishing a **NetNTLMv2 challenge-response** from an NT password hash or reusable credential.
- Recognizing the operator-noted causal chain while distinguishing it from independently verified evidence: reported poisoned name resolution, NTLM over HTTP, manual submission of a privileged credential, offline recovery, and credential reuse. The public derivatives do not independently establish the specific fallback-resolution protocol or the redacted recovery result.
- Separating the failed SMB capture observation from Nmap's independent SMB-server-signing result and avoiding unsupported causality.
- Treating a verified Event 4624 Logon Type 3 as proof of successful network authentication—not proof of code execution—while keeping the current transcription explicitly pending raw-export verification.
- Keeping attacker-side tool output separate from target-side confirmation.
- Recording timestamp and evidence-provenance limitations instead of normalizing or inventing chronology.
- Translating evidence gaps into specific collection and validation tasks.

## Evidence handling

See [`evidence/screenshots/README.md`](evidence/screenshots/README.md) for the sanitized screenshot manifest, hashes, dimensions, supported claims, and limitations. Do not add live credentials, challenge-response material, raw sensitive logs, VM disks, or packet captures without review and sanitization. See `.gitignore` for local artifact exclusions.

## Read next

- [`incident-report.md`](incident-report.md) — investigation, evidence assessment, and validation gaps.
- [`docs/build-guide.md`](docs/build-guide.md) — authorized-lab build notes and reproduction workflow with secrets omitted.
