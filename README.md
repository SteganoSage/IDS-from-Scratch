
# IDS From Scratch (C++)
This is my personal project where I am trying to build a simple Intrusion Detection System (IDS) **from scratch using C++**.  
The goal is to learn how IDS systems like Snort work internally by implementing the basic components myself.

I am doing this project as part of a self project, where I code and study small parts of the IDS every day.

---

## 📌 Project Aim
- Understand how network packets are captured and processed  
- Learn how signature-based detection works  
- Try simple anomaly detection ideas  
- Build some basic HIDS (Host IDS) features later  
- Improve my C++ skills, networking knowledge, and understanding of cybersecurity tools  

This is mainly a **learning-focused** project, not a production-ready IDS.

---

## 📁 Project Structure

```
ids-from-scratch/
│
├── src/                 → C++ source files
├── include/             → Header files
├── modules/             → Detection modules (signature, anomaly, etc.)
├── config/              → Settings, rule files
├── alerts/              → Generated alerts (JSON or text)
├── docs/                → Notes, diagrams, explanations
├── test-pcaps/          → Sample PCAPs for testing
└── CMakeLists.txt       → Build configuration
```

---

## 🧩 Features I Plan to Add
I will be adding features step by step as I learn.

### ✔ Basic Setup  
- [x] C++ project structure  
- [x] CMake build  
- [x] GitHub repo  

### 🔄 In Progress  
- Packet capture using libpcap  
- Parsing Ethernet/IP/TCP headers  
- Simple rule matching  
- JSON alert output  

### 🔮 Future Features (as I learn)  
- Signature-based detection  
- Anomaly detection (SYN flood, port scan, etc.)  
- Flow/session tracking  
- File Integrity Monitoring  
- Log Monitoring  

This list will change as I progress.

---

## 🔧 Build Instructions

### Install dependencies (Ubuntu):
```bash
sudo apt update
sudo apt install build-essential cmake libpcap-dev nlohmann-json3-dev libssl-dev
```

### Clone and build:
```bash
git clone https://github.com/YOUR_USERNAME/ids-from-scratch
cd ids-from-scratch

mkdir build
cd build
cmake ..
make
```

### Run:
```bash
./ids
```

---

## 📝 Why I Am Doing This Project
I want to:
- improve my C++ skills  
- understand how IDS tools actually work  
- learn networking in a practical way  
- build a project that I can show in future interviews  

I am treating this as a hands-on learning journey rather than trying to create a perfect IDS.

---

## 📄 Notes & Documentation
I am adding simple notes here:  
```
/docs/architecture.md  
/docs/progress.md  
```

This helps me keep track of what I learn each day.

---

## 📌 Disclaimer
This is an educational project.  
It is NOT meant to be used as a real security tool.  
I am building this only to learn and understand how IDS systems function internally.

---

