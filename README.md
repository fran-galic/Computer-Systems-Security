# Computer Systems Security – Laboratory Exercises

This repository contains my work and notes for the laboratory exercises of the course *Computer Systems Security* (FER, 2024/2025).

Note: not all labs required coding — some deliverables were notes, reports, and configuration scripts as specified in the assignments.

## Lab 1: Symmetric Cryptography – Password Manager
The task was to design and implement a prototype password manager that securely stores (address, password) pairs using symmetric cryptography.  
Main functionalities:
- Initialize an empty password database
- Store or replace a password for a given address
- Retrieve the password for a given address

Security requirements:
- Passwords must remain confidential (no leakage of equality, length, or reuse)
- Addresses must remain confidential (attacker learns only the number of stored addresses)
- Integrity must be preserved (no unauthorized modification or swapping of passwords)

The implementation had to use a master password, with keys derived via a secure key derivation function (e.g., PBKDF2, Argon2). Suggested libraries were PyCryptodome (Python) or Java JCE.

---

## Lab 2: Buffer Overflow Exploitation
The goal was to identify and exploit stack-based buffer overflows in the provided vulnerable web server `zookws`.

Key tasks:
- Inspect C source code (`zookd.c`, `http.c`) and locate a buffer overflow that can overwrite the return address
- Craft an input that crashes the process
- Develop exploits to execute arbitrary code when stack execution is enabled, and use return-to-libc or ROP techniques when it is not

The lab was carried out in a controlled VM environment with tools such as GDB, strace, and Python for exploit automation.

---

## Lab 3: Web Application Vulnerabilities
This lab used DVWA (Damn Vulnerable Web Application) to explore common web application security issues.  
Official lab materials are available here: [srs-lab GitLab repository](https://gitlab.tel.fer.hr/srs/srs-lab)

Tasks included:
1. Command Injection: executing arbitrary system commands (e.g., reading `/etc/passwd`)
2. SQL Injection: extracting password hashes from the `users` table and recovering plaintext passwords
3. Cross-Site Scripting (XSS): injecting JavaScript to steal cookies (PHPSESSID) and send them to a logging server
4. File Inclusion: manipulating GET parameters to read system files and analyzing results

The focus was on both successful exploitation and describing mitigations (input validation, output encoding, access control).

---

## Lab 4: Network Protocol Security and Firewall
The final lab was performed using the IMUNES network emulator. The topology included Internet, DMZ, and Private segments, with a firewall (FW) in between.  
Official lab materials are available here: [srs-lab GitLab repository](https://gitlab.tel.fer.hr/srs/srs-lab)

Main tasks:
- Run and analyze services such as HTTP, SSH, DNS, Telnet across different network zones
- Use Wireshark and nmap to study protocol behavior and detect active services
- Configure a firewall script (`FW.sh`) to enforce specific access policies:
  - Restrict access to services based on zone and protocol
  - Allow only necessary traffic between DMZ, Private, and Internet
  - Ensure SSH access is limited to designated administration hosts
- Analyze captured traffic (`syn_scan.pcap`) to identify scanning hosts, targets, and open/closed ports

Deliverables included a configuration script (`FW.sh`) and a written summary of findings.
