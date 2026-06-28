# Active Directory: Kerberoasting & AS-REP Roasting — Purple-Team Writeup

A purple-team study of two of the most common AD credential-access techniques: the **attack**, how
to **detect** it, and how to **defend**. Practice these safely in a lab such as
[GOAD](https://github.com/Orange-Cyberdefense/GOAD) or a TryHackMe/HTB AD path — **never** in a
production directory you don't own.

## 1. Kerberoasting (MITRE T1558.003)
**Attack:** Any domain user can request a Kerberos service ticket (TGS) for any account that has a
Service Principal Name (SPN). The ticket is encrypted with the service account's NTLM hash. If the
account uses **RC4**, the attacker cracks the ticket **offline** (Hashcat mode 13100) to recover
the password — no further interaction with the DC, so it's quiet.
```
# Red (lab): enumerate SPNs and request tickets
Rubeus.exe kerberoast /outfile:hashes.txt
# or: GetUserSPNs.py -request -dc-ip <dc> domain/user
hashcat -m 13100 hashes.txt wordlist.txt
```

**Detect:** Security **Event ID 4769** (TGS requested) with `TicketEncryptionType 0x17` (RC4) for a
**user** SPN (exclude machine accounts ending `$` and `krbtgt`). A burst of 4769s for many SPNs
from one host is a strong signal. → [`../detections/win_security_kerberoasting_4769_rc4.yml`](../detections/win_security_kerberoasting_4769_rc4.yml)

**Defend:**
- Use **group Managed Service Accounts (gMSA)** or long (25+ char) random passwords for service accounts.
- **Disable RC4**, enforce AES for Kerberos.
- Plant a **honeypot SPN account** (no real use) and alert on *any* TGS request for it.

## 2. AS-REP Roasting (MITRE T1558.004)
**Attack:** Accounts with **"Do not require Kerberos pre-authentication"** return an AS-REP that
contains crackable material — obtainable **without any credentials**.
```
# Red (lab):
GetNPUsers.py domain/ -usersfile users.txt -dc-ip <dc>
hashcat -m 18200 asrep.txt wordlist.txt
```

**Detect:** Security **Event ID 4768** (TGT requested) with `PreAuthType 0` and RC4 (`0x17`).
→ [`../detections/win_security_asreproast_4768_rc4.yml`](../detections/win_security_asreproast_4768_rc4.yml)

**Defend:** Remove "do not require pre-auth" wherever possible; strong passwords; disable RC4;
honeypot a pre-auth-disabled account and alert on requests.

## Purple-team loop
1. Execute the technique in the lab (Rubeus / Impacket).
2. Confirm the Security events fire (4769 / 4768).
3. Validate these Sigma rules trigger on them (convert → SIEM).
4. Apply the hardening, re-run, confirm the attack now fails / is high-signal.
