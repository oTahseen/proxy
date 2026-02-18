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
MAX_PROXIES_PER_REQUEST = 50
TEST_TIMEOUT = 15

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()
semaphore = asyncio.Semaphore(MAX_CONCURRENT_TESTS)

def b64_decode(data):
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding).decode()

def build_vless(link):
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
            "multiMode": query.get("mode", ["gun"])[0] == "multi"
        }

    if stream["security"] == "tls":
        stream["tlsSettings"] = {
            "serverName": query.get("sni", [""])[0],
            "allowInsecure": False
        }

    outbound = {
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

    return outbound

def build_vmess(link):
    raw = link.replace("vmess://", "")
    data = json.loads(b64_decode(raw))

    stream = {
        "network": data.get("net", "tcp"),
        "security": "tls" if data.get("tls") == "tls" else "none"
    }

    if data.get("net") == "ws":
        stream["wsSettings"] = {
            "path": data.get("path", "/"),
            "headers": {"Host": data.get("host", "")}
        }

    outbound = {
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

    return outbound

def build_trojan(link):
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

def build_ss(link):
    link = link.split("#")[0]
    raw = link.replace("ss://", "")
    decoded = b64_decode(raw)
    method_pass, server_port = decoded.split("@")
    method, password = method_pass.split(":")
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
                async with session.get("https://www.google.com") as r:
                    await r.text()
                latency = (time.time() - start) * 1000

                async with session.get("http://ip-api.com/json") as r:
                    ipinfo = await r.json()

                return {
                    "latency": round(latency, 2),
                    "ip": ipinfo.get("query"),
                    "country": ipinfo.get("country"),
                    "link": link
                }

        except:
            return None
        finally:
            proc.terminate()
            os.remove(config_path)

async def process_links(message, links):
    links = [l.strip() for l in links if l.strip()]
    await message.answer(f"Testing {len(links)} proxies...")

    tasks = [test_proxy(l) for l in links]
    results = await asyncio.gather(*tasks)

    working = [r for r in results if r]

    if not working:
        await message.answer("No working proxies.")
        return

    working.sort(key=lambda x: x["latency"])

    response = "🏆 Working Proxies:\n\n"
    for i, r in enumerate(working[:5], 1):
        response += (
            f"{i}. {r['country']} | {r['ip']}\n"
            f"⚡ {r['latency']} ms\n"
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
    content = data.read().decode()
    await process_links(message, content.splitlines())

async def main():
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
