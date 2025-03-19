# **Telstra Cybersecurity Project**  

This repository contains my solutions for the **Telstra Cybersecurity Virtual Experience Program** on **Forage**. The project simulates a real-world **Security Operations Center (SOC) response** to a **malware attack**, focusing on **threat analysis** and **technical mitigation** using Python.  

---

## **Tasks Overview**  

### **Task 1: Responding to a Malware Attack**  
- Investigated a **Security Operations Center (SOC) alert** regarding a malware attack.  
- Triaged the incident, identified initial **Indicators of Compromise (IoCs)**, and escalated to the appropriate team.  
- Documented findings and provided **incident response recommendations**.  

### **Task 2: Analyzing the Attack**  
- Examined **malware infection patterns** to determine its **spread method**.  
- Analyzed **malicious payloads** used in the attack.  
- Prepared a **firewall rule** to block the identified attack patterns.  

### **Task 3: Mitigating the Malware Attack (Technical Implementation)**  
- Developed a **Python-based firewall** to detect and block **Spring4Shell exploit attempts**.  
- Implemented pattern-matching techniques to **filter malicious payloads and headers**.  
- Tested the firewall using simulated attack requests to validate its effectiveness.  

---

## **Project Files**  

| File Name            | Description |
|----------------------|-------------|
| `firewall_server.py` | Python-based firewall server that inspects HTTP requests and blocks malicious patterns. |
| `test_requests.py` | Script that sends simulated attack requests to test the firewall’s protection. |
| `attack_analysis.txt` | Findings from malware analysis, including IoCs and observed attack behaviors. |
| `README.md` | Project documentation. |

---

## **Key Learnings**  
- Gained hands-on experience in **SOC alert triaging** and **incident response**.  
- Developed **firewall security rules** to mitigate real-world cyber threats.  
- Strengthened Python skills in **security automation** and **HTTP request filtering**.  
- Understood **malware propagation techniques** and how to contain them effectively.  

---

## **Next Steps**  
- Implement **real-time logging and alerting** for blocked requests.  
- Enhance the firewall with **IP-based blocking and rate limiting**.  
- Expand attack detection to **cover additional exploits** beyond Spring4Shell.  
- Integrate the firewall with **SIEM tools for centralized monitoring**.  

---

## **References**  
- [Spring4Shell Vulnerability (CVE-2022-22965)](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965)  
- [Python HTTP Server Documentation](https://docs.python.org/3/library/http.server.html)  
- [Forage - Telstra Cybersecurity Program](https://www.theforage.com/)  
