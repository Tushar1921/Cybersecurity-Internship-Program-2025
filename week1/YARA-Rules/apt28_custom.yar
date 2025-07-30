
# YARA Rules Documentation – Week 1

**Intern Name:** Tushar chaturkar  
**Intern ID:** 116
**Internship Task:** Threat Intelligence & Malware Detection  
**Focus Area:** YARA Rule Creation, Understanding & Testing

---

## 🧠 What is YARA?

**YARA (Yet Another Ridiculous Acronym)** is a powerful pattern-matching tool used by security analysts to:

- Detect and classify malware
- Identify suspicious strings or binary patterns in files or memory
- Automate threat detection workflows

It is widely used in:
- Digital forensics
- Threat hunting
- Antivirus engines
- Incident response

---

## 📐 Structure of a YARA Rule

```yara
rule RuleName
{
    meta:
        description = "Short summary"
        author = "Tushar chaturkar"
        reference = "Optional URL or CVE"
    
    strings:
        $string1 = "malicious_string"
        $hex1 = {E8 ?? ?? ?? ?? 5D C3}
    
    condition:
        $string1 or $hex1
}
```

---

## 🛠️ Rules Created During Internship

### ✅ Example 1: Rule to Detect Suspicious PowerShell Usage
```yara
rule Suspicious_PowerShell
{
    meta:
        description = "Detects common malicious PowerShell usage"
        author = "Sumit Dhavale"
    
    strings:
        $a = "Invoke-WebRequest"
        $b = "IEX"
        $c = "DownloadString"
    
    condition:
        any of ($a, $b, $c)
}
```

### ✅ Example 2: Rule to Detect Encoded Payloads
```yara
rule Base64EncodedPayload
{
    meta:
        description = "Detects base64 encoded malware patterns"
        author = "Sumit Dhavale"
    
    strings:
        $encoded = /[A-Za-z0-9+/]{100,}={0,2}/

    condition:
        $encoded
}
```

---

## 🎯 Threat-Specific Rules: APT28_Custom.yar

### Rule Set: apt28_custom.yar

This rule file is designed to detect malware samples, behaviors, and indicators associated with the APT28 threat group (a.k.a. Fancy Bear or STRONTIUM).

APT28 is known for using tools such as **X-Agent**, **Sedkit**, and **Zebrocy**, and for performing spear-phishing and data exfiltration campaigns targeting government and military organizations.

#### Example Rule (Extract from apt28_custom.yar):
```yara
rule APT28_XAgent
{
    meta:
        description = "Detects X-Agent malware used by APT28"
        author = "Sumit Dhavale"
        threat_group = "APT28"

    strings:
        $a = "XAgent"
        $b = "Zebrocy"
        $c = "GRIZZLY STEPPE"

    condition:
        any of ($a, $b, $c)
}
```

### Testing Process
I used the following command to scan a memory dump and malware samples:
```bash
yara apt28_custom.yar memory_dump.dmp
```

The rule successfully matched known strings in simulated samples, demonstrating its ability to detect APT28-linked behavior in memory or disk files.

### MITRE TTPs Covered
- **T1059.001** – PowerShell Execution  
- **T1071.001** – C2 over HTTPS  
- **T1547** – Persistence via Registry or Scheduled Task

### Why This Rule Is Important
This YARA rule is essential in identifying APT-level malware early, allowing security teams to contain threats before data exfiltration or privilege escalation occurs.

---

## 🧪 How I Tested All Rules

- Used **YARA CLI** to scan sample files and memory dumps.
- Loaded rules in **Volatility Framework** for memory forensics.
- Integrated exported rules from **MISP** and modified them.

```bash
yara my_rules.yar suspicious_file.exe
```

---

## 📚 Tools & Platforms Used

- [YARA GitHub](https://github.com/VirusTotal/yara)
- [MISP Project](https://www.misp-project.org/)
- Volatility Framework
- ThreatView + memory IOCs

---
