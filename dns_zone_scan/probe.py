"""Active probes: ICMP ping, TCP connect, HTTP/HTTPS GET."""

from __future__ import annotations

import ipaddress
import platform
import re
import socket
import subprocess
import time

import requests
import urllib3

UA = "Mozilla/5.0 (dns-zone-scan; DNS hygiene audit)"
IS_WINDOWS = platform.system() == "Windows"

# Probes read certificates separately (certs.py), so unverified HTTPS is intended. Disabled process-wide:
# warnings.catch_warnings() is not thread-safe and leaked warnings under the parallel probes.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def icmp(ip: str, timeout: float = 2.0, count: int = 2) -> dict:
    v6 = ipaddress.ip_address(ip).version == 6
    if IS_WINDOWS:
        cmd = ["ping", "-6" if v6 else "-4", "-n", str(count), "-w", str(int(timeout * 1000)), ip]
    else:
        cmd = ["ping", "-6" if v6 else "-4", "-c", str(count), "-W", str(int(max(1, timeout))), ip]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout * count + 5,
                           creationflags=0x08000000 if IS_WINDOWS else 0)
        out = p.stdout
        # Windows returns 0 for "Destination host unreachable"; a real echo reply has TTL / ttl=
        # (Windows IPv6 replies carry no TTL, only "time=12ms" / "time<1ms")
        ok = bool(re.search(r"ttl[=:]", out, re.IGNORECASE)) or (v6 and bool(re.search(r"time[=<]", out)))
        rtt = None
        m = re.search(r"(?:Average|avg)[^=]*=\s*([\d.]+)", out) or re.search(r"/([\d.]+)/[\d.]+/[\d.]+ ms", out)
        if m:
            rtt = float(m.group(1))
        return {"reply": ok, "rtt_ms": rtt if ok else None}
    except Exception as e:  # noqa: BLE001
        return {"reply": False, "error": type(e).__name__}


def tcp(host: str, port: int, timeout: float = 4.0) -> dict:
    t0 = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return {"open": True, "ms": round((time.monotonic() - t0) * 1000, 1)}
    except socket.timeout:
        return {"open": False, "error": "timeout"}
    except ConnectionRefusedError:
        return {"open": False, "error": "refused"}
    except OSError as e:
        return {"open": False, "error": (e.strerror or type(e).__name__)[:80]}


def _classify_req_error(e: Exception) -> str:
    s = str(e)
    if isinstance(e, requests.exceptions.ConnectTimeout):
        return "connect timeout"
    if isinstance(e, requests.exceptions.ReadTimeout):
        return "read timeout"
    if isinstance(e, requests.exceptions.SSLError):
        return "TLS error"
    if "refused" in s.lower() or "10061" in s:
        return "refused"
    if "getaddrinfo" in s or "Name or service not known" in s or "NameResolution" in s:
        return "DNS failure"
    if "reset" in s.lower() or "10054" in s:
        return "connection reset"
    if isinstance(e, requests.exceptions.ConnectionError):
        return "connection error"
    return type(e).__name__


def http(host: str, scheme: str, timeout: float = 6.0) -> dict:
    url = f"{scheme}://{host}/"
    t0 = time.monotonic()
    try:
        r = requests.get(url, timeout=(timeout, timeout), allow_redirects=False, verify=False,
                         headers={"User-Agent": UA}, stream=True)
        body = b""
        try:
            for chunk in r.iter_content(4096):
                body += chunk
                if len(body) >= 4096:
                    break
        except Exception:  # noqa: BLE001
            pass
        r.close()
        title = None
        m = re.search(rb"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
        if m:
            title = m.group(1).decode("utf-8", errors="replace").strip()[:120]
        hdr = r.headers
        return {
            "responded": True,
            "url": url,
            "status": r.status_code,
            "reason": r.reason,
            "server": hdr.get("Server"),
            "location": hdr.get("Location"),
            "via": hdr.get("Via"),
            "content_type": hdr.get("Content-Type"),
            "powered_by": hdr.get("X-Powered-By"),
            "cdn_headers": {k: v for k, v in hdr.items() if k.lower() in (
                "cf-ray", "x-amz-cf-id", "x-amz-cf-pop", "x-cache", "x-served-by", "x-goog-generation",
                "x-cloud-trace-context", "x-amzn-requestid", "x-azure-ref")},
            "title": title,
            "ms": round((time.monotonic() - t0) * 1000, 1),
        }
    except Exception as e:  # noqa: BLE001
        return {"responded": False, "url": url, "error": _classify_req_error(e), "detail": str(e)[:300]}


def ipv6_available(timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection(("2001:4860:4860::8888", 53), timeout=timeout):
            return True
    except OSError:
        return False
