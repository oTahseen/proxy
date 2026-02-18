import asyncio
import aiohttp
import uuid
import os
import time
import base64
import json
import subprocess
from urllib.parse import urlparse, parse_qs

from aiogram import Bot, Dispatcher, types, F
from aiogram.filters import CommandStart
from aiohttp_socks import ProxyConnector

# ==========================================
# CONFIG
# ==========================================

BOT_TOKEN = "6469497752:AAH1V_At-4f56MAziV-VuoPqFXlk1IT0TF8"
XRAY_PATH = "/usr/local/x-ui/bin/xray-linux-amd64"

MAX_CONCURRENT_TESTS = 3
MAX_PROXIES_PER_REQUEST = 200
TEST_TIMEOUT = 15

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()
semaphore = asyncio.Semaphore(MAX_CONCURRENT_TESTS)

# ==========================================
# SAFE PROXY PARSERS
# ==========================================

def safe_base64_decode(data: str):
    try:
        data = data.encode("ascii", errors="ignore").decode()
        padding = "=" * (-len(data) % 4)
        return base64.urlsafe_b64decode(data + padding).decode("utf-8")
    except Exception:
        return None


def parse_ss(link: str):
    try:
        link = link.split("#")[0].strip()
        raw = link.replace("ss://", "")

        # Case 1: Entire thing base64 encoded
        if "@" not in raw:
            decoded = safe_base64_decode(raw)
            if not decoded:
                return None
            method_password, server_port = decoded.split("@")
        else:
            method_password, server_port = raw.split("@")

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
    except Exception:
        return None


def parse_trojan(link: str):
    try:
        link = link.split("#")[0].strip()
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
    except Exception:
        return None


def parse_vless(link: str):
    try:
        link = link.split("#")[0].strip()
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
    except Exception:
        return None


def build_outbound(link: str):
    try:
        if link.startswith("ss://"):
            return parse_ss(link)
        elif link.startswith("trojan://"):
            return parse_trojan(link)
        elif link.startswith("vless://"):
            return parse_vless(link)
    except Exception:
        return None
    return None


# ==========================================
# XRAY CONFIG
# ==========================================

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


# ==========================================
# TEST PROXY
# ==========================================

async def test_proxy(link: str):

    async with semaphore:

        outbound = build_outbound(link)
        if not outbound:
            return {"link": link, "error": "Invalid or unsupported"}

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
            connector = ProxyConnector.from_url(proxy_url)

            async with aiohttp.ClientSession(
                connector=connector,
                timeout=timeout
            ) as session:

                # Latency
                start = time.time()
                async with session.get("https://www.google.com") as resp:
                    await resp.text()
                latency = (time.time() - start) * 1000

                # Speed test (5MB)
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

        except Exception:
            result = {"link": link, "error": "Connection failed"}

        finally:
            proc.terminate()
            if os.path.exists(config_path):
                os.remove(config_path)

        return result


# ==========================================
# PROCESS LINKS
# ==========================================

async def process_links(message: types.Message, links):

    cleaned = []
    for l in links:
        l = l.strip()
        if not l:
            continue
        l = l.replace(" ", "")
        cleaned.append(l)

    if not cleaned:
        await message.answer("⚠️ No proxy links found.")
        return

    if len(cleaned) > MAX_PROXIES_PER_REQUEST:
        await message.answer(
            f"⚠️ Maximum {MAX_PROXIES_PER_REQUEST} proxies per request."
        )
        return

    await message.answer(f"🔍 Testing {len(cleaned)} proxies...")

    tasks = [test_proxy(link) for link in cleaned]
    results = await asyncio.gather(*tasks)

    working = [r for r in results if "score" in r]
    failed = [r for r in results if "error" in r]

    if not working:
        await message.answer("❌ No working proxies found.")
        return

    working.sort(key=lambda x: x["score"], reverse=True)

    response = "🏆 *Best Proxies:*\n\n"

    for i, r in enumerate(working[:5], 1):
        response += (
            f"{i}. ⚡ {r['latency']} ms | "
            f"{r['speed']} Mbps\n"
        )

    response += f"\n\n✅ Working: {len(working)}"
    response += f"\n❌ Failed: {len(failed)}"

    await message.answer(response, parse_mode="Markdown")


# ==========================================
# HANDLERS (AIOGRAM V3)
# ==========================================

@dp.message(CommandStart())
async def start_handler(message: types.Message):
    await message.answer(
        "👋 Send proxy links (one per line)\n"
        "or upload a .txt file containing proxy configs."
    )

@dp.message(F.text & ~F.text.startswith("/"))
async def text_handler(message: types.Message):
    links = message.text.strip().splitlines()
    await process_links(message, links)

@dp.message(F.document)
async def document_handler(message: types.Message):

    document = message.document

    if not document.file_name.endswith(".txt"):
        await message.answer("⚠️ Please upload a .txt file only.")
        return

    file = await bot.get_file(document.file_id)
    downloaded = await bot.download_file(file.file_path)
    content = downloaded.read().decode("utf-8", errors="ignore")

    links = content.strip().splitlines()
    await process_links(message, links)


# ==========================================
# START BOT
# ==========================================

async def main():
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
