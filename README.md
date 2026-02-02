# 🔧 Network Diagnostic Toolkit  
A lightweight yet powerful network diagnostic tool written in C.  
This program combines the functionality of tools like **ping**, **nc**, **dig**, and **arp-scan** into a single interactive CLI application.

This software is released under the **GNU General Public License v3.0 (GPL‑3.0)**, ensuring that it remains free and open for all users to study, modify, and redistribute under the same license terms.

---

## 🚀 Features

### **1. TCP Connection Test**
- Test connectivity to any host using TCP.
- Supports:
  - HTTP (port 80)
  - HTTPS (port 443)
  - Custom port input
- Useful for checking open ports and service availability.

---

### **2. UDP Connection Test**
- Sends a UDP packet to a target host and waits for a response.
- Helps identify:
  - Open UDP ports
  - Filtered or unreachable services

---

### **3. ICMP Connection Test (⚠️ Requires Root Privilege)**
- Sends raw ICMP Echo Requests (similar to `ping`).
- Displays:
  - Sent packets
  - Received replies
  - Success rate
- Uses **raw sockets**, which require root privileges.

---

### **4. Specific Port Test (TCP + UDP)**
- Tests both TCP and UDP connectivity to a given port.
- Useful for firewall testing and service diagnostics.

---

### **5. DNS Query Tool (⚠️ Requires Root Privilege)**
Performs advanced DNS lookups using low‑level resolver APIs:

- A (IPv4)
- AAAA (IPv6)
- MX (Mail Exchange)
- NS (Name Server)
- PTR (Reverse Lookup)

Supports:
- System DNS
- Custom DNS server input

Some systems require elevated privileges for low‑level DNS operations.

---

### **6. Find MAC Address on Local Network**
- Lists all available network interfaces and their assigned IP addresses.
- Allows selecting an interface by number.
- Sends an ARP request to the target IP.
- Displays the MAC address if the host responds.
- Useful for:
  - Network discovery
  - ARP troubleshooting
  - Device identification

---

### **7. Exit**
Cleanly exits the program.

---

## 🛠️ How to Compile

### **Using the provided script**
```bash
chmod +x compile.sh
sudo ./compile.sh
```

---

### **Manual Compilation**

#### **Requirements**
- GCC or any C compiler

Install GCC on Debian‑based systems:

```bash
sudo apt-get install -y gcc
```

#### **Linux Compilation**
```bash
gcc net.c -o net -Wall -Wextra -Wpedantic -lresolv
```

`libresolv` is required for DNS parsing functions (`ns_initparse`, `ns_parserr`, etc.).

---

### **UNIX / Solaris Compilation**
Some UNIX variants require additional networking libraries:

```bash
gcc net.c -o net -Wall -Wextra -Wpedantic -lresolv -lnsl -lsocket
```

⚠️ **Do NOT use `-lsocket` or `-lnsl` on Linux** — these libraries do not exist there.

---

## ⚠️ Root Privilege Requirements

Two features require **root execution level**:

### 🔥 ICMP Connection Test  
Uses raw ICMP sockets → requires root.

### 🔥 DNS Query Tool  
Uses low‑level resolver APIs → may require root depending on system configuration.

Run the program with:

```bash
sudo ./net
```

---

## 📂 Project Structure

```
net.c
functions.h
compile.sh
README.md
LICENSE
```

---

## 👤 Author

**Mehmet Lotfi**

📺 **YouTube:** @Khorshid_Computer  
📢 **Telegram:** @Source_Code_Store

---

## ⭐ License  
This project is licensed under the **GNU General Public License v3.0 (GPL‑3.0)**.  
You are free to use, modify, and redistribute this software under the terms of the GPL‑3.0.  
See the `LICENSE` file for the full text of the license.