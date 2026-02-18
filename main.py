import asyncio
import aiohttp
import uuid
import os
import time
import base64
import json
import subprocess
from urllib.parse import urlparse, parse_qs
from aiogram import Bot, Dispatcher, types

# =========================
# CONFIG
# =========================

BOT_TOKEN = "6469497752:AAH1V_At-4f56MAziV-VuoPqFXlk1IT0TF8"
XRAY_PATH = "/usr/local/x-ui/bin/xray-linux-amd64"
MAX_CONCURRENT_TESTS = 3
TEST_TIMEOUT = 15

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()

semaphore = asyncio.Semaphore(MAX_CONCURRENT_TESTS)

# =========================
# PARSERS
# =========================

def parse_ss(link):
    raw = link.replace("ss://", "")
    decoded = base64.urlsafe_b64decode(raw + "===").decode()
    method_password, server_port = decoded.split("@")
    method, password = method_password.split(":")
    server, port = server_port.split(":")
    return {
        "protocol": "shadowsocks",
        "settings": {
            "servers": [{
                "address": server,
                "port": int(port),
                "method": method,
                "password": password
            }]
        }
    }

def parse_trojan(link):
    parsed = urlparse(link)
    return {
        "protocol": "trojan",
        "settings": {
            "servers": [{
                "address": parsed.hostname,
                "port": parsed.port,
                "password": parsed.username
            }]
        }
    }

def parse_vless(link):
    parsed = urlparse(link)
    query = parse_qs(parsed.query)
    return {
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": parsed.hostname,
                "port": parsed.port,
                "users": [{
                    "id": parsed.username,
                    "encryption": "none"
                }]
            }]
        },
        "streamSettings": {
            "network": query.get("type", ["tcp"])[0],
            "security": query.get("security", ["none"])[0]
        }
    }

def build_outbound(link):
    if link.startswith("ss://"):
        return parse_ss(link)
    elif link.startswith("trojan://"):
        return parse_trojan(link)
    elif link.startswith("vless://"):
        return parse_vless(link)
    else:
        return None

# =========================
# XRAY CONFIG GENERATOR
# =========================

def generate_config(outbound, socks_port):
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "port": socks_port,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {"udp": True}
        }],
        "outbounds": [outbound]
    }

# =========================
# TEST FUNCTION
# =========================

async def test_proxy(link):

    async with semaphore:

        outbound = build_outbound(link)
        if not outbound:
            return {"link": link, "error": "Unsupported protocol"}

        test_id = str(uuid.uuid4())
        socks_port = 20000 + int(uuid.uuid4().int % 10000)
        config_path = f"/tmp/xray_test_{test_id}.json"

        config = generate_config(outbound, socks_port)

        with open(config_path, "w") as f:
            json.dump(config, f)

        proc = subprocess.Popen(
            [XRAY_PATH, "-config", config_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        await asyncio.sleep(2)

        proxy_url = f"socks5://127.0.0.1:{socks_port}"

        try:
            timeout = aiohttp.ClientTimeout(total=TEST_TIMEOUT)
            connector = aiohttp.ProxyConnector.from_url(proxy_url)

            async with aiohttp.ClientSession(
                connector=connector,
                timeout=timeout
            ) as session:

                # LATENCY TEST
                start = time.time()
                async with session.get("https://www.google.com") as resp:
                    await resp.text()
                latency = (time.time() - start) * 1000

                # SPEED TEST (5MB)
                start = time.time()
                async with session.get(
                    "https://speed.cloudflare.com/__down?bytes=5000000"
                ) as resp:
                    await resp.read()
                duration = time.time() - start
                speed_mbps = (5 * 8) / duration

                score = (1000 / latency) * 0.4 + speed_mbps * 0.6

                result = {
                    "link": link,
                    "latency": round(latency, 2),
                    "speed": round(speed_mbps, 2),
                    "score": round(score, 2)
                }

        except Exception as e:
            result = {"link": link, "error": str(e)}

        proc.terminate()
        os.remove(config_path)

        return result

# =========================
# TELEGRAM HANDLER
# =========================

@dp.message()
async def handle_message(message: types.Message):

    links = message.text.strip().splitlines()

    await message.reply("🔍 Testing proxies...")

    tasks = [test_proxy(link.strip()) for link in links if link.strip()]
    results = await asyncio.gather(*tasks)

    working = [r for r in results if "score" in r]
    failed = [r for r in results if "error" in r]

    working.sort(key=lambda x: x["score"], reverse=True)

    response = "🏆 *Results:*\n\n"

    for i, r in enumerate(working[:5], 1):
        response += (
            f"{i}. ⚡ {r['latency']} ms | "
            f"{r['speed']} Mbps\n"
        )

    if failed:
        response += f"\n❌ Failed: {len(failed)}"

    await message.reply(response, parse_mode="Markdown")

# =========================
# START
# =========================

async def main():
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
