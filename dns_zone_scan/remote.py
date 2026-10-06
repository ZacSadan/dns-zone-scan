"""Remote probing through the Globalping network (https://globalping.io, free, no API key).

Used for IPv6 when the scanning machine has no IPv6 connectivity: ICMP ping of IPv6 addresses and
HTTP/HTTPS over IPv6 for names that have AAAA records. Anonymous limit: 250 tests/hour per client IP.
"""

from __future__ import annotations

import time

import requests

API = "https://api.globalping.io/v1/measurements"
UA = "dns-zone-scan (DNS hygiene audit)"


def _submit(body: dict) -> dict:
    try:
        r = requests.post(API, json=body, timeout=20, headers={"User-Agent": UA})
        remaining = r.headers.get("X-RateLimit-Remaining")
        if r.status_code == 202:
            return {"id": r.json()["id"], "remaining": remaining}
        err = r.json().get("error", {}) if "json" in r.headers.get("Content-Type", "") else {}
        return {"error": f"HTTP {r.status_code}: {err.get('message') or r.text[:120]}", "remaining": remaining}
    except Exception as e:  # noqa: BLE001
        return {"error": f"{type(e).__name__}: {e}"[:200]}


def _wait(ids: list[str], timeout: float = 90) -> dict[str, dict]:
    done: dict[str, dict] = {}
    deadline = time.monotonic() + timeout
    pending = list(ids)
    while pending and time.monotonic() < deadline:
        time.sleep(1.5)
        for mid in list(pending):
            try:
                d = requests.get(f"{API}/{mid}", timeout=20, headers={"User-Agent": UA}).json()
            except Exception:  # noqa: BLE001
                continue
            if d.get("status") != "in-progress":
                done[mid] = d
                pending.remove(mid)
    for mid in pending:
        done[mid] = {"status": "timeout", "results": []}
    return done


def _probe_label(p: dict) -> str:
    return f"{p.get('city') or ''} {p.get('country') or ''} ({p.get('network') or '?'})".strip()


def _ping_summary(m: dict) -> dict:
    probes, replied, rtts = [], False, []
    for res in m.get("results", []):
        st = (res.get("result") or {}).get("stats") or {}
        ok = (st.get("rcv") or 0) > 0
        replied |= ok
        if ok and st.get("avg") is not None:
            rtts.append(st["avg"])
        probes.append({"probe": _probe_label(res.get("probe") or {}), "rcv": st.get("rcv"), "loss": st.get("loss"),
                       "avg_ms": st.get("avg"), "status": (res.get("result") or {}).get("status")})
    if not probes:
        return {"reply": None, "error": f"remote measurement {m.get('status')}", "via": "globalping"}
    return {"reply": replied, "rtt_ms": min(rtts) if rtts else None, "via": "globalping", "probes": probes}


def _http_summary(m: dict, url: str) -> dict:
    for res in m.get("results", []):
        r = res.get("result") or {}
        probe = _probe_label(res.get("probe") or {})
        if r.get("statusCode"):
            hdr = {k.lower(): v for k, v in (r.get("headers") or {}).items()}
            loc = hdr.get("location")
            return {"responded": True, "url": url, "status": r["statusCode"], "reason": r.get("statusCodeName"),
                    "server": hdr.get("server") if isinstance(hdr.get("server"), str) else None,
                    "location": loc if isinstance(loc, str) else None,
                    "resolved": r.get("resolvedAddress"), "via": "globalping", "probe": probe}
        raw = (r.get("rawOutput") or r.get("status") or "no response").strip()
        return {"responded": False, "url": url, "error": raw[:120], "via": "globalping", "probe": probe}
    return {"responded": False, "url": url, "error": f"remote measurement {m.get('status')}", "via": "globalping"}


def ipv6_checks(ips: list[str], hosts: list[str], probes_per_ping: int = 2) -> dict:
    """Ping each IPv6 address and GET each hostname over IPv6 (HTTP + HTTPS) from remote probes."""
    jobs = []  # (kind, key, url, submit-result)
    for ip in ips:
        jobs.append(("ping", ip, None, _submit({"type": "ping", "target": ip, "limit": probes_per_ping,
                                                "measurementOptions": {"packets": 3}})))
    for host in hosts:
        for proto in ("HTTP", "HTTPS"):
            jobs.append(("http", host, f"{proto.lower()}://{host}/", _submit({
                "type": "http", "target": host, "limit": 1,
                "measurementOptions": {"protocol": proto, "ipVersion": 6,
                                       "request": {"method": "HEAD", "path": "/"}}})))
    results = _wait([j[3]["id"] for j in jobs if "id" in j[3]])
    # A single probe can fail for its own reasons (local resolver, policy errors such as "Private IP ranges are
    # not allowed") - retry failed HTTP checks once on another probe before calling the target down.
    retry = []
    for i, (kind, key, url, sub) in enumerate(jobs):
        if kind == "http" and "id" in sub and not _http_summary(results.get(sub["id"], {}), url).get("responded"):
            proto = "HTTPS" if url.startswith("https") else "HTTP"
            new = _submit({"type": "http", "target": key, "limit": 1,
                           "measurementOptions": {"protocol": proto, "ipVersion": 6,
                                                  "request": {"method": "HEAD", "path": "/"}}})
            if "id" in new:
                retry.append((i, new))
    if retry:
        results.update(_wait([n["id"] for _, n in retry]))
        for i, new in retry:
            kind, key, url, old = jobs[i]
            if _http_summary(results.get(new["id"], {}), url).get("responded"):
                jobs[i] = (kind, key, url, new)

    out = {"service": "globalping.io", "ping": {}, "http": {}, "https": {},
           "remaining_quota": next((j[3].get("remaining") for j in reversed(jobs) if j[3].get("remaining")), None)}
    for kind, key, url, sub in jobs:
        if "error" in sub:
            res = {"reply": None, "error": sub["error"], "via": "globalping"} if kind == "ping" else \
                  {"responded": False, "url": url, "error": sub["error"], "via": "globalping"}
        elif kind == "ping":
            res = _ping_summary(results.get(sub["id"], {}))
        else:
            res = _http_summary(results.get(sub["id"], {}), url)
        if kind == "ping":
            out["ping"][key] = res
        else:
            out["https" if url.startswith("https") else "http"][key] = res
    return out
