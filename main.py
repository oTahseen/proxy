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

BOT_TOKEN = "6469497752:AAH1V_At-4f56MAziV-VuoPqFXlk1IT0TF8"
XRAY_PATH = "/usr/local/x-ui/bin/xray-linux-amd64"

MAX_CONCURRENT_TESTS = 3
MAX_PROXIES_PER_REQUEST = 200
TEST_TIMEOUT = 15

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()
semaphore = asyncio.Semaphore(MAX_CONCURRENT_TESTS)

def safe_base64_decode(data: str):
    try:
        data = data.encode("ascii", errors="ignore").decode()
        padding = "=" * (-len(data) % 4)
        return base64.urlsafe_b64decode(data + padding).decode("utf-8")
    except:
        return None

def parse_ss(link: str):
    try:
        link = link.split("#")[0].strip()
        raw = link.replace("ss://", "")
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
    except:
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
    except:
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
    except:
        return None

def build_outbound(link: str):
    if link.startswith("ss://"):
        return parse_ss(link)
    if link.startswith("trojan://"):
        return parse_trojan(link)
    if link.startswith("vless://"):
        return parse_vless(link)
    return None

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

async def test_proxy(link: str):
    async with semaphore:
        outbound = build_outbound(link)
        if not outbound:
            return {"error": "invalid"}

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

            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                start = time.time()
                async with session.get("https://www.google.com") as resp:
                    await resp.text()
                latency = (time.time() - start) * 1000

                start = time.time()
                async with session.get("https://speed.cloudflare.com/__down?bytes=5000000") as resp:
                    await resp.read()
                duration = time.time() - start
                speed_mbps = (5 * 8) / duration

                async with session.get("http://ip-api.com/json") as resp:
                    ipinfo = await resp.json()

                score = (1000 / latency) * 0.4 + speed_mbps * 0.6

                result = {
                    "latency": round(latency, 2),
                    "speed": round(speed_mbps, 2),
                    "score": round(score, 2),
                    "ip": ipinfo.get("query"),
                    "country": ipinfo.get("country"),
                    "link": link
                }

        except:
            result = {"error": "failed"}

        finally:
            proc.terminate()
            if os.path.exists(config_path):
                os.remove(config_path)

        return result

async def process_links(message: types.Message, links):
    cleaned = [l.strip().replace(" ", "") for l in links if l.strip()]
    if not cleaned:
        await message.answer("No proxy links found.")
        return
    if len(cleaned) > MAX_PROXIES_PER_REQUEST:
        await message.answer(f"Maximum {MAX_PROXIES_PER_REQUEST} proxies per request.")
        return

    await message.answer(f"Testing {len(cleaned)} proxies...")

    tasks = [test_proxy(link) for link in cleaned]
    results = await asyncio.gather(*tasks)

    working = [r for r in results if "score" in r]
    failed = len(results) - len(working)

    if not working:
        await message.answer("No working proxies found.")
        return

    working.sort(key=lambda x: x["score"], reverse=True)

    response = "🏆 Best Proxies:\n\n"

    for i, r in enumerate(working[:5], 1):
        response += (
            f"{i}. {r['country']} | {r['ip']}\n"
            f"⚡ {r['latency']} ms | {r['speed']} Mbps\n"
            f"<code>{r['link']}</code>\n\n"
        )

    response += f"Working: {len(working)}\nFailed: {failed}"

    await message.answer(response, parse_mode="HTML")

@dp.message(CommandStart())
async def start_handler(message: types.Message):
    await message.answer("Send proxy links (one per line) or upload a .txt file.")

@dp.message(F.text & ~F.text.startswith("/"))
async def text_handler(message: types.Message):
    await process_links(message, message.text.strip().splitlines())

@dp.message(F.document)
async def document_handler(message: types.Message):
    document = message.document
    if not document.file_name.endswith(".txt"):
        await message.answer("Upload a .txt file only.")
        return
    file = await bot.get_file(document.file_id)
    downloaded = await bot.download_file(file.file_path)
    content = downloaded.read().decode("utf-8", errors="ignore")
    await process_links(message, content.splitlines())

async def main():
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
