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

def check_breaches(email):
    """Check HaveIBeenPwned for data breaches"""
    key = os.getenv('HIBP_KEY')
    if not key:
        return ["HIBP API key required"]
    
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
    headers = {
        'User-Agent': 'EmailOSINT-Tool',
        'hibp-api-key': key
    }
    try:
        resp = requests.get(url, headers=headers)
        if resp.status_code == 200:
            return [r.json()['Name'] for r in resp.json()]
        elif resp.status_code == 404:
            return []
        else:
            return [f"HIBP error: {resp.status_code}"]
    except Exception as e:
        return [f"HIBP error: {str(e)}"]

def hunter_domains(email):
    """Find associated domains/emails via Hunter.io"""
    key = os.getenv('HUNTER_KEY')
    if not key:
        return [{"email": "Hunter API key required", "role": "N/A"}]
    
    domain = email.split('@')[1]
    url = f"https://api.hunter.io/v2/domain-search?domain={domain}&limit=5&api_key={key}"
    try:
        resp = requests.get(url)
        data = resp.json()
        if data['data']['emails']:
            return [{'email': e['value'], 'role': e['type']} for e in data['data']['emails']]
        return []
    except:
        return []

def gravatar_image(email):
    """Get Gravatar profile image"""
    hash_email = hashlib.md5(email.lower().encode()).hexdigest()
    url = f"https://www.gravatar.com/avatar/{hash_email}?s=200&d=mp&r=g"
    try:
        resp = requests.head(url)
        return url if resp.status_code == 200 else None
    except:
        return None

def vt_reputation(domain):
    """Check VirusTotal reputation (domain check)"""
    key = os.getenv('VT_KEY')
    if not key:
        return "VirusTotal API key required"
    
    url = "https://www.virustotal.com/vtapi/v2/domain/report"
    params = {
        'apikey': key,
        'domain': domain
    }
    try:
        resp = requests.get(url, params=params)
        data = resp.json()
        if data.get('response_code') == 1:
            positives = data['positives']
            return f"{positives}/90 scanners flagged | [View](https://virustotal.com/gui/domain/{domain})"
        return "No detections"
    except:
        return "VT API error"

def generate_html_report(email, results):
    """Generate professional HTML report"""
    breaches = results['breaches']
    domains = results['domains']
    gravatar = results['gravatar']
    vt_info = results['vt_info']
    
    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>EmailOSINT Report - {email}</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 900px; margin: auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; border-left: 5px solid #e74c3c; padding-left: 15px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #3498db; color: white; }}
        .breach {{ background: #ffebee; }}
        .gravatar {{ max-width: 120px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.2); }}
        .status {{ padding: 8px 15px; border-radius: 20px; color: white; font-weight: bold; }}
        .safe {{ background: #27ae60; }}
        .warning {{ background: #f39c12; }}
        .danger {{ background: #e74c3c; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>📧 EmailOSINT Report</h1>
        <p><strong>Email:</strong> {email}</p>
        <p><strong>Generated:</strong> {results['timestamp']}</p>
        
        <h2>🔓 Data Breaches ({len(breaches)} found)</h2>
        {'' if not breaches else f'<div class="breach"><ul>' + ''.join([f'<li>{b}</li>' for b in breaches]) + '</ul></div>' or '<p>✅ No breaches found</p>'}
        
        <h2>🌐 Associated Domains</h2>
        {pd.DataFrame(domains).to_html(classes='table', table_id='domains', border=0) if domains else '<p>❌ No associated domains found</p>'}
        
        <h2>👤 Profile Picture</h2>
        {f'<img src="{gravatar}" class="gravatar" alt="Gravatar">' if gravatar else '<p>❌ No Gravatar found</p>'}
        
        <h2>🛡️ Domain Reputation</h2>
        <p class="status {'danger' if 'flagged' in vt_info else 'safe'}">{vt_info}</p>
    </div>
</body>
</html>
    """
    return html_content

def main():
    print("🚀 EmailOSINT - Automated Email Reconnaissance")
    print("=" * 50)
    
    email = input("📧 Enter target email: ").strip()
    if '@' not in email:
        print("❌ Invalid email format!")
        return
    
    print("🔍 Gathering intelligence...")
    
    # Run all checks
    domain = email.split('@')[1]
    results = {
        'email': email,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'breaches': check_breaches(email),
        'domains': hunter_domains(email),
        'gravatar': gravatar_image(email),
        'vt_info': vt_reputation(domain)
    }
    
    # Generate report
    report_filename = f"report_{email.replace('@', '_').replace('.', '_')}.html"
    html_report = generate_html_report(email, results)
    
    with open(report_filename, 'w', encoding='utf-8') as f:
        f.write(html_report)
    
    # Print summary
    print("\n✅ Analysis complete!")
    print(f"📊 Report saved: {report_filename}")
    print(f"🔓 Breaches: {len(results['breaches'])}")
    print(f"🌐 Domains: {len(results['domains'])}")
    print("🎯 Open the HTML file in your browser!")

if __name__ == "__main__":
    main()
