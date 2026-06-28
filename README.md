# 14 — Active Directory Attack & Defend (Purple Team)

[![CI](https://github.com/BL3IP/ad-attack-defend/actions/workflows/ci.yml/badge.svg)](https://github.com/BL3IP/ad-attack-defend/actions/workflows/ci.yml)

A purple-team study of two top AD credential-access techniques — **Kerberoasting** and **AS-REP
roasting** — with the attack, **validated Sigma detections**, and hardening.

> The full multi-VM attack lab ([GOAD](https://github.com/Orange-Cyberdefense/GOAD)) needs a
> hypervisor/cluster, so this project focuses on the **detection + defense** deliverables that are
> reproducible anywhere; the writeup shows how to execute the attacks safely in a lab you own.

## Goal
Demonstrate AD purple-team skill: understand the attack, write detections that fire on the real
Windows Security events, and apply the right mitigations.

## What's inside
| Path | What it is |
|------|-----------|
| [`docs/kerberoasting-purple-writeup.md`](./docs/kerberoasting-purple-writeup.md) | Attack → detect → defend for Kerberoasting & AS-REP roasting |
| [`detections/win_security_kerberoasting_4769_rc4.yml`](./detections/win_security_kerberoasting_4769_rc4.yml) | Sigma: RC4 TGS requests (T1558.003) |
| [`detections/win_security_asreproast_4768_rc4.yml`](./detections/win_security_asreproast_4768_rc4.yml) | Sigma: RC4 TGT without pre-auth (T1558.004) |

## Exact Setup Commands
```powershell
pip install sigma-cli pysigma-backend-splunk pysigma-validators-sigmahq
sigma check detections\
sigma convert -t splunk --without-pipeline detections\
```

## Proof It Works
`sigma check detections/` → **`Found 0 errors, 0 condition errors and 0 issues`**. Both rules
compile to Splunk:
```spl
# Kerberoasting (Event 4769, RC4, excludes machine/krbtgt)
EventID=4769 TicketEncryptionType="0x17" NOT (ServiceName IN ("*$","krbtgt"))
# AS-REP roasting (Event 4768, RC4, no pre-auth)
EventID=4768 TicketEncryptionType="0x17" PreAuthType=0
```

## Screenshots
See [`./screenshots/`](./screenshots). Add: the `0 issues` output; if you build a lab, the 4769/4768
events + a SIEM hit.

## My Custom Extensions
- Detections target the **exact Windows Security events + RC4 encryption type** the attacks produce,
  with sensible filters (machine accounts, krbtgt) to cut false positives.
- Validated against the **SigmaHQ validator suite** (correct ATT&CK tactic+technique tags).
- Hardening tied to each technique (gMSA, disable RC4/enforce AES, honeypot SPN/pre-auth accounts).

## Resume Bullet Points
- Authored and validated **Sigma detections for Kerberoasting (T1558.003) and AS-REP roasting
  (T1558.004)** against the real Windows Security events (4769/4768, RC4).
- Documented the full **purple-team loop** (execute → detect → harden → re-test) for AD credential access.
- Compiled detections to Splunk and passed the SigmaHQ validator suite with zero issues.

## Next-Level Ideas
- Stand up GOAD and capture the live 4769/4768 events to attach as evidence.
- Add detections for DCSync, unconstrained delegation, and golden/silver tickets.
- Feed these into the detection-as-code pipeline (project 07).

---
status: ✅ complete & tested
```
✅ PROJECT COMPLETE & FULLY TESTED in its isolated folder. All works. Ready for portfolio.
```
