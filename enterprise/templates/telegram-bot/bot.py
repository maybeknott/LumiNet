#!/usr/bin/env python3
"""
LumiNet VPS & Cloudflare Management Telegram Bot Template

Provides system administration capabilities over a secure chat interface.
Enables server resource tracking, service control, Cloudflare DNS updates,
and user proxy credential management.

Required Libraries:
  pip install pyTelegramBotAPI requests psutil

Configure Environment Variables before running:
  export TELEGRAM_BOT_TOKEN="your-bot-token"
  export ADMIN_CHAT_ID="your-telegram-chat-id"
  export CLOUDFLARE_API_TOKEN="your-cloudflare-token"
  export CLOUDFLARE_ZONE_ID="your-zone-id"
"""

import os
import sys
import psutil
import subprocess
import requests
import telebot
from telebot.types import ReplyKeyboardMarkup, KeyboardButton

# Configurations
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
ADMIN_CHAT_ID = os.getenv("ADMIN_CHAT_ID")
CF_API_TOKEN = os.getenv("CLOUDFLARE_API_TOKEN")
CF_ZONE_ID = os.getenv("CLOUDFLARE_ZONE_ID")

if not BOT_TOKEN:
    print("Error: TELEGRAM_BOT_TOKEN environment variable must be set.")
    sys.exit(1)

bot = telebot.TeleBot(BOT_TOKEN)

# Security check middleware
def is_admin(message):
    if ADMIN_CHAT_ID and str(message.chat.id) != str(ADMIN_CHAT_ID):
        bot.reply_to(message, "⚠️ Unauthorized: You are not configured as the Administrator of this node.")
        return False
    return True

# Admin Keyboard Markup
def admin_keyboard():
    markup = ReplyKeyboardMarkup(row_width=2, resize_keyboard=True)
    markup.add(
        KeyboardButton("📊 System Status"),
        KeyboardButton("⚙️ Restart Services"),
        KeyboardButton("🌐 CF DNS Records"),
        KeyboardButton("🛡️ CF Strict SSL"),
        KeyboardButton("🔑 Generate User Key")
    )
    return markup

@bot.message_handler(commands=['start', 'menu'])
def send_welcome(message):
    if not is_admin(message):
        return
    bot.send_message(
        message.chat.id,
        "🌐 *LumiNet VPS & Cloudflare Operations Bot Console*\nSelect an administrative command below:",
        parse_mode="Markdown",
        reply_markup=admin_keyboard()
    )

@bot.message_handler(func=lambda msg: msg.text == "📊 System Status")
def check_status(message):
    if not is_admin(message):
        return
    
    cpu = psutil.cpu_percent(interval=1)
    ram = psutil.virtual_memory().percent
    disk = psutil.disk_usage('/').percent
    
    # Check Proxy Service state
    services = ["xray", "sing-box", "v2ray", "luminet"]
    service_status = ""
    for s in services:
        try:
            # Check if service is active via systemctl
            res = subprocess.run(["systemctl", "is-active", s], capture_output=True, text=True)
            status = res.stdout.strip()
            if status == "active":
                service_status += f"🟢 `{s}`: Active\n"
            else:
                service_status += f"🔴 `{s}`: {status}\n"
        except FileNotFoundError:
            # Systemctl not available (e.g. non-systemd system)
            service_status += f"⚪ `{s}`: Missing systemctl\n"

    status_msg = (
        f"📊 *VPS Telemetry Dashboard*\n"
        f"───────────────────\n"
        f"💻 *CPU Usage:* {cpu}%\n"
        f"💾 *RAM Usage:* {ram}%\n"
        f"💿 *Disk Usage:* {disk}%\n"
        f"───────────────────\n"
        f"⚙️ *Proxy Core Services:*\n{service_status}"
    )
    bot.send_message(message.chat.id, status_msg, parse_mode="Markdown")

@bot.message_handler(func=lambda msg: msg.text == "⚙️ Restart Services")
def restart_services(message):
    if not is_admin(message):
        return
    
    bot.send_message(message.chat.id, "🔄 Restarting proxy and console daemon services...")
    
    restart_targets = ["luminet", "xray", "sing-box"]
    log = ""
    for t in restart_targets:
        try:
            res = subprocess.run(["systemctl", "restart", t], capture_output=True, text=True)
            if res.returncode == 0:
                log += f"✅ `{t}` restarted successfully.\n"
            else:
                log += f"❌ `{t}` fail: {res.stderr.strip() or 'Unknown error'}\n"
        except Exception as e:
            log += f"❌ `{t}` error: {str(e)}\n"
            
    bot.send_message(message.chat.id, f"🔄 *Restart Audit Log*\n───────────────────\n{log}", parse_mode="Markdown")

@bot.message_handler(func=lambda msg: msg.text == "🌐 CF DNS Records")
def get_cf_dns(message):
    if not is_admin(message):
        return
    
    if not CF_API_TOKEN or not CF_ZONE_ID:
        bot.send_message(message.chat.id, "❌ Error: Cloudflare credentials (API Token / Zone ID) not set.")
        return

    url = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records"
    headers = {
        "Authorization": f"Bearer {CF_API_TOKEN}",
        "Content-Type": "application/json"
    }

    try:
        resp = requests.get(url, headers=headers)
        data = resp.json()
        if not data.get("success"):
            bot.send_message(message.chat.id, f"❌ Cloudflare API Error:\n{data.get('errors')}")
            return
        
        records = data.get("result", [])
        log = ""
        for r in records[:10]: # Limit to first 10 records for readability
            proxied = "☁️ Proxied" if r.get("proxied") else "⚡ DNS Only"
            log += f"• `{r.get('name')}` ({r.get('type')}) ➔ `{r.get('content')}` [{proxied}]\n"
            
        bot.send_message(message.chat.id, f"🌐 *Cloudflare DNS Records*\n───────────────────\n{log}", parse_mode="Markdown")
    except Exception as e:
        bot.send_message(message.chat.id, f"❌ Connection Error: {str(e)}")

@bot.message_handler(func=lambda msg: msg.text == "🛡️ CF Strict SSL")
def get_cf_ssl(message):
    if not is_admin(message):
        return
    
    if not CF_API_TOKEN or not CF_ZONE_ID:
        bot.send_message(message.chat.id, "❌ Error: Cloudflare credentials not configured.")
        return

    url = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/settings/ssl"
    headers = {
        "Authorization": f"Bearer {CF_API_TOKEN}",
        "Content-Type": "application/json"
    }

    try:
        resp = requests.get(url, headers=headers)
        data = resp.json()
        if not data.get("success"):
            bot.send_message(message.chat.id, f"❌ Cloudflare Setting Fetch Error:\n{data.get('errors')}")
            return
        
        ssl_value = data.get("result", {}).get("value")
        bot.send_message(
            message.chat.id, 
            f"🛡️ *Cloudflare SSL Posture Status*\n───────────────────\nActive Mode: *{ssl_value.upper()}*\n\nUse /set_ssl [off|flexible|full|strict] to update.",
            parse_mode="Markdown"
        )
    except Exception as e:
        bot.send_message(message.chat.id, f"❌ Connection Error: {str(e)}")

@bot.message_handler(commands=['set_ssl'])
def set_cf_ssl(message):
    if not is_admin(message):
        return
    
    args = telebot.util.extract_arguments(message.text).strip().lower()
    if args not in ["off", "flexible", "full", "strict"]:
        bot.reply_to(message, "❌ Invalid value. Usage: /set_ssl [off|flexible|full|strict]")
        return
        
    url = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/settings/ssl"
    headers = {
        "Authorization": f"Bearer {CF_API_TOKEN}",
        "Content-Type": "application/json"
    }
    payload = {"value": args}

    try:
        resp = requests.patch(url, headers=headers, json=payload)
        data = resp.json()
        if data.get("success"):
            bot.send_message(message.chat.id, f"✅ Cloudflare SSL posture successfully set to: *{args.upper()}*", parse_mode="Markdown")
        else:
            bot.send_message(message.chat.id, f"❌ Cloudflare Update Error:\n{data.get('errors')}")
    except Exception as e:
        bot.send_message(message.chat.id, f"❌ Connection Error: {str(e)}")

@bot.message_handler(func=lambda msg: msg.text == "🔑 Generate User Key")
def generate_user_key(message):
    if not is_admin(message):
        return
    
    import uuid
    new_uuid = str(uuid.uuid4())
    bot.send_message(
        message.chat.id,
        f"🔑 *Generated V2Ray/VLESS User UUID:*\n`{new_uuid}`\n\n_Add this UUID to your daemon config or server's list of valid users, then restart the service._",
        parse_mode="Markdown"
    )

if __name__ == "__main__":
    print("Starting LumiNet System Admin Bot loop...")
    bot.infinity_polling()
