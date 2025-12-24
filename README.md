# # Case Study – NAIPAY

# APT1337 Canary – Incident Response & Forensic Investigation (Wazuh SIEM)

## Team Members
- **Mitchelle Lagat**
- Joseph Ngatia
- Elaine Mbugua


##  Overview
This project documents a full **incident response and forensic investigation** of a simulated Advanced Persistent Threat (APT) attack attributed to **APT1337 Canary** on CTF ROOM.  
The investigation was conducted using **Wazuh SIEM** across both **Linux (Ubuntu 24.04)** and **Windows Server 2022** endpoints.

The objective was to reconstruct the complete **attack lifecycle**, identify the **initial access vector**, analyze **privilege escalation**, **persistence mechanisms**, **lateral movement**, and extract actionable **Indicators of Compromise (IOCs)**.

This Case Study was completed as part of the **KamiLimu Cybersecurity Program**, built in partnership with **Serianu**, whose industry collaboration enabled hands-on exposure to real-world incident response workflows and SIEM-based forensic investigations.

---

##  Investigation Objectives
- Reconstruct the **attack timeline**
- Identify the **initial access vector**
- Analyze **privilege escalation techniques**
- Detect **persistence mechanisms**
- Investigate **command-and-control (C2)** and **lateral movement**
- Extract and document **Indicators of Compromise (IOCs)**
- Map attacker behavior to the **MITRE ATT&CK framework**

---
## Investigation Approach
- Collected and analyzed endpoint and network telemetry using **Wazuh SIEM**
- Correlated Linux authentication logs and Windows Security/Sysmon events
- Reconstructed attacker activity by pivoting on timestamps, source IPs, and user accounts
- Validated findings using MITRE ATT&CK techniques
- Documented findings into timelines, IOC tables, and a final incident response report

---
##  Skills Demonstrated
- Incident Response & Digital Forensics  
- SIEM Log Analysis (Wazuh)  
- Linux & Windows Security Analysis  
- Threat Hunting & Log Correlation  
- Attack Timeline Reconstruction  
- MITRE ATT&CK Mapping  
- Security Reporting & Documentation  

---

##  Tools & Technologies
- **Wazuh SIEM**
- **Sysmon**
- Linux authentication & system logs
- Windows Event Logs (Security, System, Sysmon)
- MITRE ATT&CK Framework
- Velociraptor (dual-use tool analysis)
- Kibana / Wazuh Dashboards

---

##  Environment
| Component | Details |
|---------|--------|
| Linux Endpoint | Ubuntu 24.04 |
| Windows Endpoint | Windows Server 2022 |
| SIEM | Wazuh |
| Log Sources | SSH, Auth logs, Sysmon, Windows Security logs |

---

##  Attack Summary
The attacker simulated an APT-style intrusion leveraging **credential-based access** followed by **privilege escalation**, **persistence**, and **lateral movement** across Linux and Windows systems.

### Key Observed Tactics
- SSH and RDP credential abuse
- Privilege escalation using `sudo`, `su`, and Windows token manipulation
- Persistence via services, scheduled tasks, and registry run keys
- Defense evasion by attempting to disable security agents
- Use of legitimate tools for malicious purposes (Living-off-the-Land)

---

##  MITRE ATT&CK Mapping (Examples)
| Tactic | Technique |
|------|----------|
| Initial Access | Valid Accounts (T1078) |
| Privilege Escalation | Sudo / Token Manipulation |
| Persistence | Scheduled Tasks / Services |
| Lateral Movement | Remote Services (T1021) |
| Defense Evasion | Impair Defenses (T1562) |

---

## Deliverables
- **Full Incident Response Report (PDF)**
- Linux Attack Timeline
- Windows Attack Timeline
- Indicators of Compromise (IOC) tables
- MITRE ATT&CK mapping
- Remediation and prevention recommendations

---


---

## Indicators of Compromise (IOC Examples)
- Suspicious SSH login attempts
- Abnormal Windows process creation events
- Unauthorized service creation
- Unexpected scheduled tasks
- Known malicious IP addresses and user accounts

---

## Key Lessons Learned
- Early detection of credential abuse is critical in preventing lateral movement.
- Correlating low-level logs provides greater visibility than relying on alerts alone.
- Defense evasion attempts are strong indicators of advanced threat activity.
- Proper log retention and centralized monitoring significantly improve response capability.

---

##  Disclaimer
This project was conducted in a **controlled, simulated environment** for educational and defensive security purposes only.  
All data and attacks were part of an authorized cybersecurity exercise.

---


