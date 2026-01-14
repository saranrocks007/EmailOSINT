# 📧 EmailOSINT - FREE Email Reconnaissance Tool

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python&logoColor=yellow)](https://python.org)

**EmailOSINT** automates professional-grade OSINT reconnaissance on email addresses using **100% FREE APIs**. No paid services required!

## 🎯 What It Does
🔍 Input: single email address
✅ Output: Beautiful HTML report with:

Associated domains/emails (Hunter.io FREE)

Domain reputation (VirusTotal FREE 500/day)

Disposable email detection

WHOIS company info

## 🚀 Quick Start 
```bash
git clone https://github.com/YOURUSERNAME/EmailOSINT.git
cd EmailOSINT
pip install -r requirements.txt

# Get FREE API keys (optional but recommended)
cp .env.example .env
# Edit .env with your keys from hunter.io & virustotal.com

python email_osint.py john.doe@gmail.com
✅ Generates: report_john_doe_gmail_com.html (open in browser)

📊 Live Demo
Sample Report

🔑 FREE API Keys (Optional)
Service	Free Tier	Link
Hunter.io	50 req/month	Domains/Emails
VirusTotal	500 req/day	Reputation
No keys? Still works → Local analysis + Gravatar + WHOIS

🛠️ Features
🎨 Professional HTML reports with charts/tables

🌐 5 OSINT sources 

💰 100% FREE - No paid APIs

⚡ Production-ready error handling

🚀 GitHub Actions ready

📁 File Structure

EmailOSINT/
├── email_osint.py      # Main tool
├── requirements.txt    # Dependencies
├── .env.example       # API key template
├── demo/             # Sample reports
├── tests/            # Unit tests
└── README.md         # You're reading it!

🎮 Usage Examples

# Basic scan
python email_osint.py test@gmail.com

# Professional email
python email_osint.py ceo@company.com

# Bulk scan (add to script)
python email_osint.py user@target-corp.com
🛡️ Ethical Use Policy
text
⚠️  For authorized security testing ONLY
✅ Penetration testing with permission
✅ Red team engagements
✅ Threat intelligence research
❌ Spam/phishing/stalking


🙌 Acknowledgments
Built with ❤️ for the cybersecurity community.
Skills demonstrated: Python • OSINT • API Integration • Automation • Web Scraping



