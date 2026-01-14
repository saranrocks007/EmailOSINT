import requests
import os
from dotenv import load_dotenv
from bs4 import BeautifulSoup
import pandas as pd
from datetime import datetime
import hashlib
import json

# Load environment variables
load_dotenv()

def hunter_domains(email):
    """Find associated domains/emails via Hunter.io FREE tier"""
    key = os.getenv('HUNTER_KEY')
    if not key:
        return [{"email": "Hunter.io free key needed (50 req/mo)", "role": "N/A", "note": "Signup: hunter.io"}]
    
    domain = email.split('@')[1]
    url = f"https://api.hunter.io/v2/domain-search?domain={domain}&limit=5&api_key={key}"
    try:
        resp = requests.get(url)
        data = resp.json()
        if data['data']['emails']:
            return [{'email': e['value'], 'role': e['type'], 'confidence': e['confidence']} for e in data['data']['emails']]
        return []
    except Exception as e:
        return [{'email': f"Error: {str(e)}", 'role': 'N/A'}]

def gravatar_image(email):
    """Get Gravatar profile image (always free)"""
    hash_email = hashlib.md5(email.lower().encode()).hexdigest()
    url = f"https://www.gravatar.com/avatar/{hash_email}?s=200&d=mp&r=g"
    try:
        resp = requests.head(url, timeout=5)
        return url if resp.status_code == 200 else None
    except:
        return None

def vt_reputation(domain):
    """Check VirusTotal domain reputation (free tier: 500 req/day)"""
    key = os.getenv('VT_KEY')
    if not key:
        return "VirusTotal free key needed | Signup: virustotal.com/gui/join-us"
    
    url = "https://www.virustotal.com/vtapi/v2/domain/report"
    params = {'apikey': key, 'domain': domain}
    try:
        resp = requests.get(url, params=params, timeout=10)
        data = resp.json()
        if data.get('response_code') == 1:
            positives = data['positives']
            total = data['total']
            status = "🟢 Clean" if positives == 0 else f"🔴 {positives}/{total} scanners"
            return f"{status} | [View Report](https://www.virustotal.com/gui/domain/{domain})"
        return "ℹ️ No analysis / New domain"
    except:
        return "VT API timeout/error"

def email_reputation_check(email):
    """Basic email pattern analysis + disposable check (always free)"""
    disposable_domains = {
        'mailinator.com', 'guerrillamail.com', '10minutemail.com', 
        'yopmail.com', 'tempmail.org', 'throwawaymail.com'
    }
    
    domain = email.split('@')[1].lower()
    issues = []
    
    if domain in disposable_domains:
        issues.append("Disposable/Temporary email")
    
    if len(email) < 5:
        issues.append("Suspiciously short")
    
    if email.count('@') != 1:
        issues.append("Invalid format")
    
    return issues if issues else ["✅ Valid professional email"]

def whois_lookup(domain):
    """Basic WHOIS data (always free, no API key)"""
    try:
        import socket
        url = f"http://whois.domaintools.com/{domain}"
        resp = requests.get(url, timeout=5)
        soup = BeautifulSoup(resp.text, 'html.parser')
        info = soup.find('dd', string='Registrant Organization:') 
        org = info.find_next_sibling('dd').text.strip() if info else "N/A"
        return f"Registered Org: {org}"
    except:
        return "WHOIS lookup unavailable"

def generate_html_report(email, results):
    """Generate professional HTML report"""
    domains = results['domains']
    gravatar = results['gravatar']
    vt_info = results['vt_info']
    reputation = results['reputation']
    whois = results['whois']
    
    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>🚀 EmailOSINT Report - {email}</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial; margin: 0; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; }}
        .container {{ max-width: 1000px; margin: auto; background: white; border-radius: 15px; box-shadow: 0 10px 30px rgba(0,0,0,0.3); overflow: hidden; }}
        .header {{ background: linear-gradient(45deg, #2c3e50, #3498db); color: white; padding: 30px; text-align: center; }}
        .content {{ padding: 30px; }}
        h2 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; margin-top: 30px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; box-shadow: 0 4px 8px rgba(0,0,0,0.1); }}
        th {{ background: #34495e; color: white; padding: 15px; }}
        td {{ padding: 15px; border-bottom: 1px solid #eee; }}
        tr:hover {{ background: #f8f9fa; }}
        .gravatar {{ max-width: 150px; border-radius: 50%; border: 5px solid #3498db; box-shadow: 0 5px 15px rgba(0,0,0,0.2); }}
        .status {{ padding: 10px 20px; border-radius: 25px; font-weight: bold; color: white; display: inline-block; margin: 5px; }}
        .safe {{ background: #27ae60; }}
        .warning {{ background: #f39c12; }}
        .danger {{ background: #e74c3c; }}
        .badge {{ background: #9b59b6; padding: 5px 15px; border-radius: 20px; color: white; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📧 EmailOSINT Intelligence Report</h1>
            <p class="badge">FREE APIs • No Paid Services • Professional Grade</p>
            <p><strong>{email}</strong></p>
        </div>
        <div class="content">
            <p><strong>Generated:</strong> {results['timestamp']}</p>
            
            <h2>🌐 Associated Domains/Emails ({len(domains)})</h2>
            {pd.DataFrame(domains).to_html(classes='table', table_id='domains', border=0, index=False, escape=False) if domains and len(domains)>0 and 'Hunter.io' not in str(domains[0]) else '<p class="warning">🔑 Hunter.io API key recommended for full results (Free tier available)</p>'}
            
            <h2>👤 Profile Picture</h2>
            {f'<img src="{gravatar}" class="gravatar" alt="Gravatar" loading="lazy">' if gravatar else '<p>❌ No Gravatar profile found</p>'}
            
            <h2>🛡️ Domain Reputation</h2>
            <p class="status {'safe' if 'Clean' in vt_info else 'warning'}">{vt_info}</p>
            
            <h2>📊 Email Analysis</h2>
            {''.join([f'<span class="status warning">{issue}</span>' for issue in reputation]) if reputation != ['✅ Valid professional email'] else '<span class="status safe">✅ Professional email - No issues detected</span>'}
            
            <h2>🏢 WHOIS Info</h2>
            <p>{whois}</p>
        </div>
    </div>
</body>
</html>
    """
    return html_content

def main():
    print("🚀 EmailOSINT - FREE Email Reconnaissance Tool")
    print("=" * 60)
    print("✅ NO PAID APIs REQUIRED")
    print("🔑 Needs: Hunter.io (free) + VirusTotal (free)")
    print()
    
    email = input("📧 Enter target email: ").strip()
    if '@' not in email:
        print("❌ Invalid email format!")
        return
    
    print("\n🔍 Scanning with FREE services...")
    
    domain = email.split('@')[1]
    results = {
        'email': email,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'domains': hunter_domains(email),
        'gravatar': gravatar_image(email),
        'vt_info': vt_reputation(domain),
        'reputation': email_reputation_check(email),
        'whois': whois_lookup(domain)
    }
    
    # Generate report
    report_filename = f"report_{email.replace('@', '_').replace('.', '_')}.html"
    html_report = generate_html_report(email, results)
    
    with open(report_filename, 'w', encoding='utf-8') as f:
        f.write(html_report)
    
    print("\n🎉 Analysis COMPLETE!")
    print(f"📊 Report: {report_filename}")
    print(f"🌐 Domains found: {len(results['domains'])}")
    print(f"🛡️ VT Status: {results['vt_info'][:50]}...")
    print("\n🔥 Open HTML file in browser for full styled report!")
    print("\n💡 Get FREE API keys:")
    print("   • Hunter.io: hunter.io (50 req/mo FREE)")
    print("   • VirusTotal: virustotal.com (500 req/day FREE)")

if __name__ == "__main__":
    main()
