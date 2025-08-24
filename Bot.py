import requests
import traceback
import subprocess
import ipaddress
import logging
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, ContextTypes, filters

# --- CONFIG ---
BOT_TOKEN = "Enter_bot_token"
VIRUSTOTAL_API_KEY = "enter_virustotal_api_key"
DEEPSEEK_API_KEY = "enter_depseek_api_key"
CHATGPT_API_KEY = "enter_ai_api_key"   # ✅ NEW ChatGPT key
IPINFO_TOKEN = ""  # optional: get free token from ipinfo.io

# --- SECURITY CONFIG ---
ALLOWED_USER_IDS = []  # leave empty = allow everyone, add IDs to restrict
ETHICAL_BLOCKLIST = ["wifi hack", "password crack", "unauthorized access", "exploit vulnerability", "brute force"]

KALI_TOOLS = {
    "nmap": "Network scanning: `nmap -sV -O -T4 <target>`",
    "metasploit": "Exploitation framework: `msfconsole` → `use exploit/...`",
    "burpsuite": "Web proxy: Launch GUI or run `burpsuite`",
    "sqlmap": "SQL injection: `sqlmap -u 'http://site.com/page?param=1' --dbs`",
    "aircrack-ng": "WiFi security audit: `aircrack-ng -w wordlist.txt capture.cap`",
    "john": "Password cracking: `john --wordlist=rockyou.txt hashes.txt`",
    "wireshark": "Packet analysis: Launch GUI or `tshark -i eth0`",
    "hydra": "Brute force: `hydra -l user -P passlist.txt ssh://192.168.1.1`",
    "nikto": "Web scanner: `nikto -h http://target.com`",
    "gobuster": "Directory brute-forcing: `gobuster dir -u http://site.com -w wordlist.txt`"
}

# --- LOGGING ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler("bot.log"), logging.StreamHandler()]
)

# --- HELPER FUNCTIONS ---
def is_authorized(user_id: int) -> bool:
    return not ALLOWED_USER_IDS or user_id in ALLOWED_USER_IDS

def contains_ethical_violation(query: str) -> bool:
    return any(term in query.lower() for term in ETHICAL_BLOCKLIST)

def is_private_ip(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except:
        return False

# --- COMMAND HANDLERS ---
async def myid(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(f"✅ Your Telegram ID: {update.effective_user.id}")

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update.effective_user.id):
        return
    await update.message.reply_text(
        "⚡ Cybersecurity Bot Activated!\n"
        "Use /help for command reference\n\n"
          "🤖 Hello! I’m your AI Assistant.\n"
        "Developed by: 0xcyber_mind\n\n"
        "Type anything to chat with me!"
    )

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update.effective_user.id):
        return
    await update.message.reply_text(
        "🔐 Available Commands:\n\n"
        "/start - Bot status\n"
        "/myid - Get your Telegram ID\n"
        "/kali - Kali Linux tools list\n"
        "/tips - Ethical hacking techniques\n"
        "/scan [ip-range] - Private network scan\n"
        "/cve [CVE-ID] - Vulnerability details\n"
        "/scanurl [url] - VirusTotal URL scan\n"
        "/checkip [ip] - IP information lookup\n"
        "/hashinfo [hash] - Identify hash type\n\n"
        "💬 You can also type normal questions for AI analysis."
    )

async def kali_tools(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update.effective_user.id):
        return
    tools_list = "🔧 Kali Linux Elite Tools:\n\n"
    for tool, desc in KALI_TOOLS.items():
        tools_list += f"▪️ <b>{tool.upper()}</b>\n<code>{desc}</code>\n\n"
    tools_list += (
        "📚 Pro Tips:\n"
        "- Use `-v` for verbose output\n"
        "- Combine tools with pipes (`| grep pattern`)\n"
        "- Use `--help` for more options\n"
        "- Workflow example: nmap → nikto → sqlmap"
    )
    await update.message.reply_text(tools_list, parse_mode="HTML")

async def hacking_tips(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update.effective_user.id):
        return
    tips = (
        "🛠️ Ethical Hacking Techniques (for authorized testing only):\n\n"
        "1️⃣ Reconnaissance:\n   - `dnsenum domain.com`\n   - `sublist3r -d domain.com`\n\n"
        "2️⃣ Vulnerability Scanning:\n   - `openvas-start`\n   - Nessus (commercial)\n\n"
        "3️⃣ Privilege Escalation:\n   - `linpeas.sh`\n   - `winpeas.exe`\n   - Search ExploitDB\n\n"
        "4️⃣ Persistence:\n   - SSH tunnels: `ssh -R 80:localhost:2222 serveo.net`\n   - Cron jobs: `crontab -e`\n\n"
        "5️⃣ Covering Tracks:\n   - Clear logs: `shred -zu file`\n   - Timestomp: Metasploit module\n\n"
        "⚠️ Legal Note: Use only on systems you own or are authorized to test."
    )
    await update.message.reply_text(tips, parse_mode="HTML")

# --- AI REPLY HANDLER ---
async def ai_reply(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update.effective_user.id):
        return
    user_message = update.message.text
    if contains_ethical_violation(user_message):
        await update.message.reply_text("🚫 Ethical Alert: Request not allowed under security guidelines.")
        return
    try:
        # ✅ Prefer ChatGPT if available
        headers = {"Authorization": f"Bearer {CHATGPT_API_KEY}", "Content-Type": "application/json"}
        payload = {
            "model": "gpt-4o-mini",
            "messages": [
                {"role": "system", "content": "You are a cybersecurity consultant. Give ethical, technical answers."},
                {"role": "user", "content": user_message}
            ],
            "max_tokens": 1500
        }
        r = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=payload, timeout=30)

        if r.status_code == 200:
            reply = r.json()["choices"][0]["message"]["content"]
            await update.message.reply_text(reply[:4000], parse_mode="HTML")
        else:
            # fallback to DeepSeek if ChatGPT fails
            headers = {"Authorization": f"Bearer {DEEPSEEK_API_KEY}", "Content-Type": "application/json"}
            payload["model"] = "deepseek-chat"
            r = requests.post("https://api.deepseek.com/v1/chat/completions", headers=headers, json=payload, timeout=30)
            if r.status_code == 200:
                reply = r.json()["choices"][0]["message"]["content"]
                await update.message.reply_text(reply[:4000], parse_mode="HTML")
            else:
                await update.message.reply_text(f"⚠️ AI API Error: {r.text}")

    except Exception as e:
        await update.message.reply_text(f"⚠️ System error: {str(e)}")
        print(traceback.format_exc())

# --- MAIN FUNCTION ---
def main():
    app = Application.builder().token(BOT_TOKEN).build()

    # Register commands
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("myid", myid))
    app.add_handler(CommandHandler("kali", kali_tools))
    app.add_handler(CommandHandler("tips", hacking_tips))

    # AI handler
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, ai_reply))

    logging.info("🚀 Cybersecurity Bot is running...")
    app.run_polling()

if __name__ == "__main__":
    main()



