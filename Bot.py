import os
import requests
import traceback
import logging
import re
import json
import aiohttp
from dotenv import load_dotenv  
from groq import Groq  # Added for Groq API integration
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, ContextTypes, filters

# Load environment variables from .env file
load_dotenv()

# --- CONFIG (All values loaded from .env; no defaults to force proper setup) ---
BOT_TOKEN = os.getenv("BOT_TOKEN")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
SECURITYTRAILS_API_KEY = os.getenv("SECURITYTRAILS_API_KEY")
HIBP_API_KEY = os.getenv("HIBP_API_KEY")
GROK_API_KEY = os.getenv("GROK_API_KEY")
GROQ_API_KEY = os.getenv("GROQ_API_KEY")  # Added for Groq free tier
GROK_API_URL = "https://api.x.ai/v1/chat/completions"

# --- SECURITY CONFIG ---
ALLOWED_USER_IDS = [int(user_id.strip()) for user_id in os.getenv("ALLOWED_USER_IDS", "").split(",") if user_id.strip()]

ETHICAL_BLOCKLIST = [
    "ddos", "ransomware", "malware creation", "botnet", "phishing page",
    "unauthorized access", "keylogger", "trojan", "rootkit"
]

# --- KNOWLEDGE BASE (Kept for command-based responses; Groq API used for intelligent QA) ---
HACKING_KNOWLEDGE = {
    "reconnaissance": {
        "passive": [
            "whois domain.com - Domain registration information",
            "nslookup/dig domain.com - DNS records",
            "Google dorking: site:target.com filetype:pdf",
            "View source code for comments/hidden elements",
            "Social media profiling",
            "Job postings (reveal technologies used)"
        ],
        "active": [
            "nmap -sn 192.168.1.0/24 - Host discovery",
            "nmap -sS -sV -O target - Service detection",
            "nmap -p- target - All ports scan",
            "nikto -h target.com - Web server scan",
            "gobuster dir -u http://target.com - Directory brute forcing"
        ]
    },
    "scanning": {
        "network": [
            "arp-scan -l - Local network device discovery",
            "nmap --script vuln target - Vulnerability scripts",
            "masscan -p1-65535 192.168.1.0/24 - Fast port scan",
            "netdiscover -r 192.168.1.0/24 - ARP discovery"
        ],
        "web": [
            "whatweb target.com - Web technology fingerprinting",
            "wpscan --url target.com --enumerate u - WordPress scan",
            "sqlmap -u 'http://target.com/page?id=1' --dbs - SQL injection",
            "dirb http://target.com wordlist.txt - Directory discovery"
        ]
    },
    "enumeration": {
        "services": [
            "enum4linux target - SMB enumeration",
            "smtp-user-enum -M VRFY -U users.txt -t target - SMTP user enum",
            "snmp-check target - SNMP enumeration",
            "rpcclient -U '' target - Null session RPC"
        ]
    },
    "exploitation": {
        "frameworks": [
            "Metasploit: msfconsole → search/exploit modules",
            "Cobalt Strike: Commercial C2 framework",
            "Empire: PowerShell post-exploitation",
            "Covenant: .NET C2 framework"
        ],
        "techniques": [
            "Buffer overflow exploitation",
            "Privilege escalation paths",
            "Credential harvesting",
            "Lateral movement techniques"
        ]
    },
    "post_exploitation": {
        "windows": [
            "mimikatz - Extract credentials from memory",
            "bloodhound - AD privilege escalation paths",
            "powershell empire agents",
            "psexec/impacket tools for lateral movement"
        ],
        "linux": [
            "LinPEAS.sh - Automated enumeration script",
            "sudo -l - Check sudo permissions",
            "find / -perm -4000 2>/dev/null - SUID binaries",
            "pspy - Process monitoring without root"
        ]
    },
    "defense": {
        "network": [
            "Implement zero-trust network architecture",
            "Deploy IDS/IPS systems (Snort/Suricata)",
            "Network segmentation and microsegmentation",
            "Regular firewall rule audits"
        ],
        "endpoint": [
            "Enable application whitelisting",
            "Deploy EDR solutions",
            "Implement secure baseline configurations",
            "Regular patch management processes"
        ],
        "application": [
            "Input validation and sanitization",
            "Secure headers implementation",
            "Regular code review processes",
            "Dependency vulnerability scanning"
        ]
    }
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

def format_response(title: str, items: list) -> str:
    """Format a list of items into a readable response"""
    formatted = f"{title}:\n\n"
    for i, item in enumerate(items, 1):
        formatted += f"{i}. {item}\n"
    return formatted

async def query_groq_api(user_question: str) -> str:
    """Query Groq API for cybersecurity response (free tier compatible)"""
    if not GROQ_API_KEY:
        return "Groq API key not configured. Falling back to Grok API."
    
    system_prompt = (
        "You are a cybersecurity expert assistant focused on ethical hacking, penetration testing, and defensive security. "
        "Provide detailed, accurate information on topics like reconnaissance, scanning, enumeration, exploitation, post-exploitation, and hardening. "
        "Always emphasize ethical use, legal compliance, and authorization. Remind users that techniques are for educational or authorized testing only. "
        "Structure responses clearly with bullet points, numbered lists, and emojis for readability. Keep responses concise yet comprehensive."
    )
    
    client = Groq(api_key=GROQ_API_KEY)
    
    try:
        completion = client.chat.completions.create(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_question}
            ],
            model="llama-3.1-8b-instant",  # Free-tier friendly; swap to "qwen/qwen3-32b" if preferred
            temperature=0.1,
            max_tokens=1000,  # Adjust to fit within free limits
            stream=False
        )
        return completion.choices[0].message.content
    except Exception as e:
        logging.error(f"Groq API error: {str(e)}")
        return "Sorry, I encountered an issue processing your request. Please try again."

# Fallback to Grok if Groq fails or not configured
async def query_grok_api(user_question: str) -> str:
    """Query Grok AI API for cybersecurity response (original, as fallback)"""
    if not GROK_API_KEY:
        return "Grok API key not configured. Please set it in your .env file."
    
    system_prompt = (
        "You are a cybersecurity expert assistant focused on ethical hacking, penetration testing, and defensive security. "
        "Provide detailed, accurate information on topics like reconnaissance, scanning, enumeration, exploitation, post-exploitation, and hardening. "
        "Always emphasize ethical use, legal compliance, and authorization. Remind users that techniques are for educational or authorized testing only. "
        "Structure responses clearly with bullet points, numbered lists, and emojis for readability. Keep responses concise yet comprehensive."
    )
    
    payload = {
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_question}
        ],
        "model": "grok-4-latest",
        "stream": False,
        "temperature": 0.1  # Low temperature for consistent, factual responses
    }
    
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {GROK_API_KEY}"
    }
    
    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(GROK_API_URL, json=payload, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    return data["choices"][0]["message"]["content"]
                else:
                    logging.error(f"Grok API error: {response.status} - {await response.text()}")
                    return "Sorry, I encountered an issue processing your request. Please try again."
        except Exception as e:
            logging.error(f"Exception in Grok API call: {str(e)}")
            return "An error occurred while generating a response. Please check your query and try again."

# --- COMMAND HANDLERS ---
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update.effective_user.id):
        await update.message.reply_text("🚫 Unauthorized access.")
        return
    await update.message.reply_text(
        "⚡ Cybersecurity Expert Assistant (Powered by 0xcybermind k)\n"
        "Ask me anything about ethical hacking and security!\n\n"
        "Use /help to see available commands\n"
        "Authorized for penetration testing use."
    )

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update.effective_user.id):
        await update.message.reply_text("🚫 Unauthorized access.")
        return
    await update.message.reply_text(
        "🔐 Cybersecurity Expert Commands:\n\n"
        "/start - Initialize bot\n"
        "/help - Show this help\n"
        "/tools - Kali Linux tools reference\n"
        "/recon - Reconnaissance techniques\n"
        "/scan - Scanning methodologies\n"
        "/enum - Enumeration methods\n"
        "/exploit - Exploitation frameworks\n"
        "/post - Post-exploitation activities\n"
        "/defense - Security hardening\n"
        "/resources - Training resources\n\n"
        "Or just ask me any cybersecurity question! (Powered by Groq AI with Grok Fallback)"
    )

async def tools_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update.effective_user.id):
        await update.message.reply_text("🚫 Unauthorized access.")
        return
    
    tools_reference = (
        "🛠️ Kali Linux Pentesting Tools Reference:\n\n"
        "Reconnaissance:\n"
        "▪️ nmap - Network scanning\n"
        "▪️ whois - Domain information\n"
        "▪️ dnsenum - DNS enumeration\n"
        "▪️ theHarvester - Email harvesting\n\n"
        
        "Scanning:\n"
        "▪️ nikto - Web server scanner\n"
        "▪️ nessus - Vulnerability scanner\n"
        "▪️ openvas - Security scanner\n"
        "▪️ wpscan - WordPress scanner\n\n"
        
        "Exploitation:\n"
        "▪️ metasploit - Exploitation framework\n"
        "▪️ burpsuite - Web proxy\n"
        "▪️ sqlmap - SQL injection\n"
        "▪️ hydra - Brute force attacks\n\n"
        
        "Post-Exploitation:\n"
        "▪️ mimikatz - Credential extraction\n"
        "▪️ bloodhound - AD visualization\n"
        "▪️ linpeas - Linux enumeration\n"
        "▪️ powerview - AD enumeration\n\n"
        
        "Wireless Testing:\n"
        "▪️ aircrack-ng - WiFi auditing\n"
        "▪️ reaver - WPS exploitation\n"
        "▪️ kismet - Wireless detection\n"
        "▪️ fern - WiFi cracker (GUI)"
    )
    await update.message.reply_text(tools_reference)

async def recon_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update.effective_user.id):
        await update.message.reply_text("🚫 Unauthorized access.")
        return
    
    response = "🔍 Reconnaissance Techniques:\n\n"
    response += "1️⃣ Passive Techniques:\n"
    for technique in HACKING_KNOWLEDGE["reconnaissance"]["passive"]:
        response += f"   ▪️ {technique}\n"
    response += "\n2️⃣ Active Techniques:\n"
    for technique in HACKING_KNOWLEDGE["reconnaissance"]["active"]:
        response += f"   ▪️ {technique}\n"
    response += "\n⚠️ Legal Note: These techniques are for authorized penetration testing only."
    
    await update.message.reply_text(response)

async def scan_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update.effective_user.id):
        await update.message.reply_text("🚫 Unauthorized access.")
        return
    
    response = "📡 Scanning Methodologies:\n\n"
    response += "1️⃣ Network Scanning:\n"
    for technique in HACKING_KNOWLEDGE["scanning"]["network"]:
        response += f"   ▪️ {technique}\n"
    response += "\n2️⃣ Web Application Scanning:\n"
    for technique in HACKING_KNOWLEDGE["scanning"]["web"]:
        response += f"   ▪️ {technique}\n"
    response += "\n⚠️ Only perform scans on systems you own or are explicitly authorized to test."
    
    await update.message.reply_text(response)

async def enum_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update.effective_user.id):
        await update.message.reply_text("🚫 Unauthorized access.")
        return
    
    response = "📋 Enumeration Methods:\n\n"
    response += "Service Enumeration:\n"
    for technique in HACKING_KNOWLEDGE["enumeration"]["services"]:
        response += f"   ▪️ {technique}\n"
    response += "\n⚠️ Enumeration should only be performed during authorized security assessments."
    
    await update.message.reply_text(response)

async def exploit_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update.effective_user.id):
        await update.message.reply_text("🚫 Unauthorized access.")
        return
    
    response = "💣 Exploitation Frameworks:\n\n"
    response += "Frameworks & Tools:\n"
    for framework in HACKING_KNOWLEDGE["exploitation"]["frameworks"]:
        response += f"   ▪️ {framework}\n"
    response += "\nTechniques:\n"
    for technique in HACKING_KNOWLEDGE["exploitation"]["techniques"]:
        response += f"   ▪️ {technique}\n"
    response += "\n⚠️ These techniques are for educational and authorized testing purposes only."
    
    await update.message.reply_text(response)

async def post_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update.effective_user.id):
        await update.message.reply_text("🚫 Unauthorized access.")
        return
    
    response = "🔓 Post-Exploitation Activities:\n\n"
    response += "Windows Systems:\n"
    for technique in HACKING_KNOWLEDGE["post_exploitation"]["windows"]:
        response += f"   ▪️ {technique}\n"
    response += "\nLinux Systems:\n"
    for technique in HACKING_KNOWLEDGE["post_exploitation"]["linux"]:
        response += f"   ▪️ {technique}\n"
    response += "\n⚠️ Post-exploitation activities require explicit written authorization."
    
    await update.message.reply_text(response)

async def defense_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update.effective_user.id):
        await update.message.reply_text("🚫 Unauthorized access.")
        return
    
    response = "🛡️ Security Hardening:\n\n"
    response += "Network Security:\n"
    for measure in HACKING_KNOWLEDGE["defense"]["network"]:
        response += f"   ▪️ {measure}\n"
    response += "\nEndpoint Security:\n"
    for measure in HACKING_KNOWLEDGE["defense"]["endpoint"]:
        response += f"   ▪️ {measure}\n"
    response += "\nApplication Security:\n"
    for measure in HACKING_KNOWLEDGE["defense"]["application"]:
        response += f"   ▪️ {measure}\n"
    
    await update.message.reply_text(response)

async def resources_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update.effective_user.id):
        await update.message.reply_text("🚫 Unauthorized access.")
        return
    
    resources = (
        "📚 Cybersecurity Learning Resources:\n\n"
        "Free Platforms:\n"
        "▪️ Hack The Box - https://www.hackthebox.com/\n"
        "▪️ TryHackMe - https://tryhackme.com/\n"
        "▪️ OverTheWire - http://overthewire.org/\n"
        "▪️ VulnHub - https://www.vulnhub.com/\n\n"
        
        "Certifications:\n"
        "▪️ OSCP - Offensive Security Certified Professional\n"
        "▪️ CEH - Certified Ethical Hacker\n"
        "▪️ CISSP - Certified Information Systems Security Professional\n"
        "▪️ GPEN - GIAC Penetration Tester\n\n"
        
        "Reference Materials:\n"
        "▪️ OWASP Testing Guide\n"
        "▪️ PTES - Penetration Testing Execution Standard\n"
        "▪️ NIST Cybersecurity Framework\n"
        "▪️ MITRE ATT&CK Framework"
    )
    await update.message.reply_text(resources)

# --- INTELLIGENT QUESTION ANSWERING (Now powered by Groq AI with Grok fallback) ---
async def intelligent_qa(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update.effective_user.id):
        return
    
    user_question = update.message.text
    if contains_ethical_violation(user_question):
        await update.message.reply_text("🚫 Request blocked under ethical guidelines.")
        return
    
    try:
        # Prefer Groq for free tier; fallback to Grok if not configured
        if GROQ_API_KEY:
            response = await query_groq_api(user_question)
            if "not configured" in response:
                response = await query_grok_api(user_question)
        else:
            response = await query_grok_api(user_question)
        await update.message.reply_text(response)
    except Exception as e:
        await update.message.reply_text("Error processing your request")
        logging.error(traceback.format_exc())

# --- MAIN FUNCTION ---
def main():
    # Validate required bot token
    if not BOT_TOKEN:
        logging.error("BOT_TOKEN is required! Please set it in your .env file.")
        return
    
    # Log warnings for optional API keys
    if not GROK_API_KEY:
        logging.warning("GROK_API_KEY not configured! Intelligent QA will fail without it or GROQ_API_KEY.")
    if not GROQ_API_KEY:
        logging.warning("GROQ_API_KEY not configured! Falling back to Grok API for Intelligent QA.")
    
    # Optional: Log if other APIs are missing (they aren't used in this script but kept for future)
    if not SHODAN_API_KEY:
        logging.info("SHODAN_API_KEY not configured (not used yet).")
    if not VIRUSTOTAL_API_KEY:
        logging.info("VIRUSTOTAL_API_KEY not configured (not used yet).")
    if not SECURITYTRAILS_API_KEY:
        logging.info("SECURITYTRAILS_API_KEY not configured (not used yet).")
    if not HIBP_API_KEY:
        logging.info("HIBP_API_KEY not configured (not used yet).")
    
    app = Application.builder().token(BOT_TOKEN).build()

    # Register commands
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("tools", tools_command))
    app.add_handler(CommandHandler("recon", recon_command))
    app.add_handler(CommandHandler("scan", scan_command))
    app.add_handler(CommandHandler("enum", enum_command))
    app.add_handler(CommandHandler("exploit", exploit_command))
    app.add_handler(CommandHandler("post", post_command))
    app.add_handler(CommandHandler("defense", defense_command))
    app.add_handler(CommandHandler("resources", resources_command))

    # Intelligent Q&A handler (Groq-powered with fallback)
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, intelligent_qa))

    logging.info("🚀 Cybersecurity Expert Bot (Groq AI Integrated with Grok Fallback) is running...")
    app.run_polling()

if __name__ == "__main__":
    main()
