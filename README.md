# IDOR--hunter
A lightweight, high-performance browser extension (Manifest V3) designed for penetration testers and ethical hackers. Features passive HTTP traffic inspection, automated IDOR/BOLA scoring, noise filtering, and AI-driven vulnerability analysis with PDF report generation. Built for ethical security research.
# 🎯 IDOR Hunter Pro v2.2 — AI-Powered Security Assessment Tool

![Manifest V3](https://img.shields.io/badge/Manifest-V3-blue.svg)
![AI Enabled](https://img.shields.io/badge/AI-Gemini%20%7C%20Groq-purple.svg)
![Security Focus](https://img.shields.io/badge/Focus-IDOR%20%26%20BOLA-red.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

**IDOR Hunter Pro** is an advanced Chrome Extension (Manifest V3) designed for penetration testers and bug bounty hunters to passively identify, analyze, and verify **Insecure Direct Object Reference (IDOR)** and **Broken Object Level Authorization (BOLA)** vulnerabilities in real-time.

---

## ✨ Key Features

* **⚡ Smart Passive Interception:** Monitors background HTTP/XHR traffic and scores API endpoints based on IDOR sensitivity (Path IDs, Query parameters, UUIDs).
* **🧹 Noise & Telemetry Filter:** Automatically filters out analytics, metrics, and tracking traffic (e.g., Hotjar, New Relic, Sentry) to reduce false positives.
* **🔬 Auto Exploit & Verification Engine:** Test original vs. modified parameters to calculate response differences instantly.
* **🤖 Multi-AI Analysis:** Integrates Google Gemini, Groq, and OpenRouter to generate root-cause analysis and remediation steps.
* **🔐 Secure Local Key Handling:** API keys are stored strictly inside Chrome's local storage (`chrome.storage.local`) with no central telemetry data collection.

---

## 🛠️ Tech Stack

* **Architecture:** Chrome Extension Manifest V3 (Service Worker based)
* **Frontend:** Modern CSS3 (Cyberpunk Theme), Inter & JetBrains Mono Fonts
* **AI Provider Integrations:** Google Gemini API, Groq Cloud API, OpenRouter API

---

## 🚀 Installation & Setup
---
**Legal Disclaimer:**
IMPORTANT: This tool is strictly developed for educational, ethical security testing, and bug bounty research on authorized targets only. The developer assumes no liability for unauthorized testing or misuse. Always adhere to legal scope guidelines and strict Responsible Disclosure policies.
1. **Clone the Repository:**
   ```bash
   git clone [https://github.com/YOUR_USERNAME/idor-hunter-pro.git](https://github.com/YOUR_USERNAME/idor-hunter-pro.git)
