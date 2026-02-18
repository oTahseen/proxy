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
TEST_TIMEOUT = 20

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()
semaphore = asyncio.Semaphore(MAX_CONCURRENT_TESTS)

def safe_b64(data):
    try:
        data = data.strip()
        padding = "=" * (-len(data) % 4)
        return base64.urlsafe_b64decode(data + padding).decode()
    except:
        return None

def build_ss(link):
    try:
        link = link.split("#")[0]
        raw = link.replace("ss://", "")

        if "@" in raw:
            part1, part2 = raw.split("@", 1)
            decoded = safe_b64(part1)

            if decoded:
                method, password = decoded.split(":")
            else:
                method, password = part1.split(":")

            server, port = part2.split(":")
        else:
            decoded = safe_b64(raw)
            if not decoded:
                return None
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
    except:
        return None

def build_trojan(link):
    try:
        link = link.split("#")[0]
        parsed = urlparse(link)
        return {
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": parsed.hostname,
                    "port": parsed.port,
                    "password": parsed.username
                }]
            },
            "streamSettings": {
                "security": "tls",
                "tlsSettings": {"serverName": parsed.hostname}
            }
        }
    except:
        return None

def build_vless(link):
    try:
        link = link.split("#")[0]
        parsed = urlparse(link)
        query = parse_qs(parsed.query)

        stream = {
            "network": query.get("type", ["tcp"])[0],
            "security": query.get("security", ["none"])[0]
        }

        if stream["security"] == "reality":
            stream["realitySettings"] = {
                "publicKey": query.get("pbk", [""])[0],
                "shortId": query.get("sid", [""])[0],
                "fingerprint": query.get("fp", ["chrome"])[0],
                "serverName": query.get("sni", [""])[0]
            }

        if stream["network"] == "ws":
            stream["wsSettings"] = {
                "path": query.get("path", ["/"])[0],
                "headers": {"Host": query.get("host", [""])[0]}
            }

        if stream["network"] == "grpc":
            stream["grpcSettings"] = {
                "serviceName": query.get("serviceName", [""])[0],
                "multiMode": False
            }

        if stream["security"] == "tls":
            stream["tlsSettings"] = {
                "serverName": query.get("sni", [""])[0],
                "allowInsecure": False
            }

        return {
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": parsed.hostname,
                    "port": parsed.port,
                    "users": [{
                        "id": parsed.username,
                        "encryption": "none",
                        "flow": query.get("flow", [""])[0]
                    }]
                }]
            },
            "streamSettings": stream
        }
    except:
        return None

def build_vmess(link):
    try:
        raw = link.replace("vmess://", "")
        decoded = safe_b64(raw)
        if not decoded:
            return None
        data = json.loads(decoded)

        stream = {
            "network": data.get("net", "tcp"),
            "security": "tls" if data.get("tls") == "tls" else "none"
        }

        if data.get("net") == "ws":
            stream["wsSettings"] = {
                "path": data.get("path", "/"),
                "headers": {"Host": data.get("host", "")}
            }

        return {
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": data["add"],
                    "port": int(data["port"]),
                    "users": [{
                        "id": data["id"],
                        "alterId": int(data.get("aid", 0)),
                        "security": data.get("scy", "auto")
                    }]
                }]
            },
            "streamSettings": stream
        }
    except:
        return None

def build_outbound(link):
    if link.startswith("vless://"):
        return build_vless(link)
    if link.startswith("vmess://"):
        return build_vmess(link)
    if link.startswith("trojan://"):
        return build_trojan(link)
    if link.startswith("ss://"):
        return build_ss(link)
    return None

def generate_config(outbound, port):
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "port": port,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {"udp": True}
        }],
        "outbounds": [outbound]
    }

async def test_proxy(link):
    async with semaphore:
        outbound = build_outbound(link)
        if not outbound:
            return None

        port = 20000 + int(uuid.uuid4().int % 10000)
        config_path = f"/tmp/{uuid.uuid4()}.json"

        with open(config_path, "w") as f:
            json.dump(generate_config(outbound, port), f)

        proc = subprocess.Popen(
            [XRAY_PATH, "-config", config_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        await asyncio.sleep(2)
        proxy = f"socks5://127.0.0.1:{port}"

        try:
            timeout = aiohttp.ClientTimeout(total=TEST_TIMEOUT)
            connector = ProxyConnector.from_url(proxy)

            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:

                start = time.time()
                async with session.get("https://1.1.1.1", ssl=False) as r:
                    await r.text()
                latency_cf = (time.time() - start) * 1000

                start = time.time()
                async with session.get(
                    "https://speed.cloudflare.com/__down?bytes=5000000"
                ) as r:
                    await r.read()
                duration = time.time() - start
                speed_mbps = (5 * 8) / duration

                async with session.get("https://www.cloudflare.com/cdn-cgi/trace") as r:
                    trace = await r.text()

                ip = "Unknown"
                country = "Unknown"

                for line in trace.splitlines():
                    if line.startswith("ip="):
                        ip = line.split("=")[1]
                    if line.startswith("loc="):
                        country = line.split("=")[1]

                score = (1000 / latency_cf) * 0.4 + speed_mbps * 0.6

                return {
                    "latency": round(latency_cf, 2),
                    "speed": round(speed_mbps, 2),
                    "country": country,
                    "ip": ip,
                    "score": score,
                    "link": link
                }

        except:
            return None

        finally:
            proc.terminate()
            if os.path.exists(config_path):
                os.remove(config_path)

async def process_links(message, links):
    links = [l.strip() for l in links if l.strip()]
    total = len(links)
    working = []
    failed = 0
    processed = 0

    status = await message.answer(
        f"Testing {total} proxies...\n\nWorking: 0\nFailed: 0\nRemaining: {total}"
    )

    async def run_test(link):
        nonlocal processed, failed, working
        result = await test_proxy(link)
        processed += 1

        if result:
            working.append(result)
        else:
            failed += 1

        if processed % 3 == 0 or processed == total:
            await status.edit_text(
                f"Testing {total} proxies...\n\n"
                f"Working: {len(working)}\n"
                f"Failed: {failed}\n"
                f"Remaining: {total - processed}"
            )

    await asyncio.gather(*(run_test(l) for l in links))

    if not working:
        await status.edit_text("No working proxies.")
        return

    working.sort(key=lambda x: x["score"], reverse=True)

    response = "🏆 Best Proxies (Cloudflare Tested):\n\n"

    for i, r in enumerate(working[:5], 1):
        response += (
            f"{i}. {r['country']} | {r['ip']}\n"
            f"⚡ {r['latency']} ms | 🚀 {r['speed']} Mbps\n"
            f"<code>{r['link']}</code>\n\n"
        )

    await message.answer(response, parse_mode="HTML")

@dp.message(CommandStart())
async def start(message: types.Message):
    await message.answer("Send proxy links or upload .txt file.")

@dp.message(F.text & ~F.text.startswith("/"))
async def text_handler(message: types.Message):
    await process_links(message, message.text.splitlines())

@dp.message(F.document)
async def doc_handler(message: types.Message):
    file = await bot.get_file(message.document.file_id)
    data = await bot.download_file(file.file_path)
    content = data.read().decode(errors="ignore")
    await process_links(message, content.splitlines())

async def main():
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
