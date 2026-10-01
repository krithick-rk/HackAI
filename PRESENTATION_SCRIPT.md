# Team LOGICRON — Hack@DAC 2026 Caliptra RTL Security Audit
## 10-Minute Presentation Script & Speaking Notes

**Project:** Hack@DAC 2026 Phase 2 Caliptra RTL Security Audit  
**Team:** Team LOGICRON (Society for Electronic Transactions and Security - SETS, Chennai, India)  
**Advisor:** A. Suganya  
**Participants:** Eswari Devi, Renita .J, Sathish Kumar, Kushana Shyam Sundar  
**Total Target Time:** ~10 Minutes (600 Seconds)  
**Presentation Deck File:** `Caliptra_RTL_Security_Analysis_Report.pptx`

---

### **Slide 1: Title Slide (0:00 – 0:45)**
> *"Good morning/afternoon everyone. We are Team LOGICRON from the Society for Electronic Transactions and Security (SETS), Chennai, India. Today, we are presenting our comprehensive security audit and verification strategy for the Caliptra Root-of-Trust Hardware SystemVerilog RTL in Hack@DAC 2026.*
> 
> *Our audit spans 29 target IP modules, divided into a sequential 3-stage security framework: Stage 0 Reconnaissance, Phase 1 AI-Orchestrated Dynamic Simulation, and Phase 2 Python SAST with AI-Assisted Validation. Let’s dive straight into our team and methodology."*

---

### **Slide 2: Team Photo & Introduction (0:45 – 1:15)**
> *"Here is Team LOGICRON. Our project advisor is Mrs. A. Suganya, and our research participants are Eswari Devi, Renita .J, Sathish Kumar, and Kushana Shyam Sundar.*
> 
> *Working out of SETS Chennai, our team combines hardware security experience, automated verification, and modern AI orchestration to tackle complex SystemVerilog security audits at scale."*

---

### **Slide 3: Security Audit Workflow & Phase Separation (1:15 – 2:00)**
> *"To ensure rigorous coverage, our audit is structured into three clean, non-overlapping phases:*
> 1. **Stage 0 (Reconnaissance):** Scope discovery, register specification triage, and security goal mapping across all 29 target IP cores.
> 2. **Phase 1 (Dynamic Analysis):** Powered by an AI Orchestrator running Claude Code CLI. It assigns isolated IP modules batch-wise to worker instances to run simulation testbenches, extracting runnable PoC exploits and waveform evidence.
> 3. **Phase 2 (Static SAST Pipeline):** Driven by our custom Python SAST engine executing parallel rule-based scanning, followed by AI root-cause filtering to eliminate false positives."*

---

### **Slide 4: Stage 0 — Target Subsystem Inventory (2:00 – 2:45)**
> *"Stage 0 mapped the entire Caliptra subsystem into 5 distinct architectural Tiers covering 29 IP modules:*
> - **Tier 1 (Crypto Cores):** 11 engines including AES, SHA-3, HMAC, ECC, and post-quantum ML-DSA.
> - **Tier 2 (Storage & Locks):** Key Vault, PCR Vault, Data Vault, and Lifecycle Controller.
> - **Tier 3 (Entropy/RNG):** CSRNG, Entropy Source, and EDN.
> - **Tier 4 (Interfaces & CPU):** VeeR EL2 RISC-V Core, SoC Interface, SPI Host, and UART.
> - **Tier 5 (Bus & Top Integration):** Top Integration, AXI/AHB Bus fabrics, and TL-UL primitives."*

---

### **Slide 5: Phase 1 — Dynamic Analysis Methodology (2:45 – 3:30)**
> *"For Phase 1 Dynamic Analysis, we pioneered an AI-orchestrated verification pipeline:*
> - We integrated **Claude Code CLI** directly with SystemVerilog simulation tools (such as Verilator and Iverilog).
> - A central **Orchestrator AI instance** scheduled isolated IP cores batch-wise to parallel worker instances.
> - Worker instances executed custom verification tools to run simulation stimulus, parse trace logs, and evaluate bugs.
> - Crucially, **every single reported vulnerability required a runnable SystemVerilog PoC exploit** to guarantee zero false positives."*

---

### **Slide 6: Phase 1 — Dynamic Results & Compute Ledger (3:30 – 4:15)**
> *"The dynamic phase yielded empirical success across all 29 IP cores:*
> - **34 confirmed security vulnerabilities** were identified with **0 false positives**.
> - **34 runnable SystemVerilog PoC exploits** with accompanying VCD/FST waveform traces were developed.
> - The dynamic pipeline consumed **7.88 Million compute tokens** across 30 worker spawns.
> - As shown in the compute ledger, top compute-heavy IPs included SHA-3 (676k tokens), Top Integration (635k tokens), and ML-DSA."*

---

### **Slide 7: Dynamic Deep Dive 1 — Key Vault Key Wiping [KV-002] (4:15 – 5:15)**
> *"Let's look at our highest-severity finding: **KV-002** in the Key Vault, rated **CVSS 8.4**.*
> 
> - **Mechanism:** When two write clients attempt simultaneous transfer, error logic triggers a multi-write error. However, instead of zeroizing only the colliding slots, it unconditionally wipes **ALL 24 key slots** in the Key Vault — including write-locked root keys.
> - **Impact:** An unprivileged client can trigger a collision with a low-privilege slot to cause a complete Denial of Service, wiping root HMAC and encryption keys across the entire RoT.
> - **Proof:** Verified in `KV-002_exploit.sv`, where a collision on Slot 1 & 2 causes `slot_zeroize_bus` to assert across all 24 slots, wiping locked Slot 0 instantly."*

---

### **Slide 8: Dynamic Deep Dive 2 — ECC Verification Register Leak [ECC-001] (5:15 – 6:15)**
> *"Our second deep dive is **ECC-001** in the Elliptic Curve Cryptography engine, rated **CVSS 8.1**.*
> 
> - **Mechanism:** The `ECC_VERIFY_R` output register holds the signature verification result. While it clears on explicit zeroize, it is **never reset when an invalid signature or malformed input triggers an error path**.
> - **Impact:** Signature Spoofing. If a legitimate signature previously set `ECC_VERIFY_R` to VALID (1), a subsequent forged signature that triggers an input error leaves the stale VALID status active for firmware to read.
> - **Proof:** Confirmed in `ECC-001_exploit.sv` via VCD waveforms."*

---

### **Slide 9: Dynamic Deep Dive 3 — Top Integration OTP Gate [INTEG-001] (6:15 – 7:15)**
> *"Our third deep dive is **INTEG-001** in `caliptra_top.sv`, rated **CVSS 7.9**.*
> 
> - **Mechanism:** The OTP fuse permission signal `otp_en_entropy_src_fw_over_i` is hardcoded to constant `MuBi8True`. This collapses the intended two-factor gate (OTP Fuse AND Software register) into pure software control.
> - **Impact:** TRNG Entropy Injection Attack. Malicious firmware alone can force the entropy source into override mode in any lifecycle state (including Production), feeding arbitrary attacker-chosen entropy into CSRNG seeds.
> - **Proof:** Verified via differential PoC exploit matching attacker-chosen seeds byte-for-byte in simulation."*

---

### **Slide 10: Hardware RTL SAST Validation Methodology (7:15 – 8:15)**
> *"Moving to Phase 2 Static Analysis, we designed a custom Python SAST scanning engine:*
> - The framework auto-traverses SystemVerilog source files and executes **10 parallel scanning modules** running concurrently.
> - Modules cover Access Control, Secure Boot, OTP/Fuse Security, Debug Interfaces, Lifecycle State, Register Protection, Memory Protection, Info Disclosure, Crypto Misuse, and Privilege Escalation.
> - Results are collected into a central database and correlated against internal security rules. Parallel execution dramatically improves coverage while reducing scan time."*

---

### **Slide 11: AI-Assisted Validation & Reporting Pipeline (8:15 – 9:15)**
> *"To ensure high-confidence reporting, findings from the SAST engine enter an **AI-Assisted Validation Pipeline** using Claude AI CLI:*
> - **Root Cause & FP Reduction:** Claude inspects RTL code intent and reachability to filter out non-exploitable noise.
> - **Duplicate Detection:** Consolidates findings sharing the same vulnerable RTL logic, attack path, or affected module.
> - **Exploit Generation:** AI automatically generates standalone SystemVerilog PoC exploits and simulation scripts.
> - **Guarantee:** Only unique, reproducible, and security-relevant vulnerabilities with confirmed PoC exploits are accepted into the final report."*

---

### **Slide 12: Synthesis & Remediation Roadmap (9:15 – 10:00)**
> *"To conclude, our remediation roadmap synthesizes dynamic and static findings into four actionable steps:
> 1. **Immediate Patching:** Apply fixes for high-severity RTL bugs (`KV-002`, `ECC-001`, `INTEG-001`).
> 2. **Reset Domain Alignment:** Re-align key lock registers across Key Vault, PCR Vault, and Data Vault to cold reset (`hard_reset_b`) so secrets are not exposed post-warm-reset.
> 3. **Automated Regression:** Run our 34 developed standalone PoC exploits against patched RTL to confirm vulnerability resolution without regressions.
> 4. **Unified Sign-Off:** Combine dynamic simulation PoCs and static SAST proofs into a single audit sign-off package.
> 
> Thank you! We welcome any questions from the panel."*
