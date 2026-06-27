"""
SpectraScan - Dark Web Recon Module
PASSIVE / ETHICAL reconnaissance only.
- No marketplace interaction, no purchases, no crawling of illegal content.
- Tor required ONLY for .onion operations (127.0.0.1:9050).
- Clearnet APIs (Ahmia, PGP, BTC, emailrep) work without Tor.
"""
import os
import re
import sys
import json
import time
import socket
import urllib.parse
from datetime import datetime
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from typing import Dict, List, Optional

# Optional dependencies
try:
    import socks  # pysocks
    SOCKS_AVAILABLE = True
except ImportError:
    SOCKS_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# ---------- Config ----------
TOR_HOST = "127.0.0.1"
TOR_PORT = 9050
TOR_PROXY = f"socks5h://{TOR_HOST}:{TOR_PORT}"
HTTP_TIMEOUT = 15
ONION_TIMEOUT = 12
REPORT_DIR = os.path.expanduser("~/.local/share/SpectraScan")
os.makedirs(REPORT_DIR, exist_ok=True)

UA = "SpectraScan-Darkweb/1.0 (+passive recon)"


# ============== HTTP helpers ==============
def _tor_proxies() -> Dict[str, str]:
    return {"http": TOR_PROXY, "https": TOR_PROXY}


def http_get(url: str, timeout: int = HTTP_TIMEOUT, via_tor: bool = False) -> Optional[str]:
    """GET URL, return body text or None."""
    try:
        headers = {"User-Agent": UA, "Accept": "*/*"}
        if via_tor and REQUESTS_AVAILABLE and SOCKS_AVAILABLE:
            r = requests.get(url, proxies=_tor_proxies(), headers=headers,
                             timeout=timeout, allow_redirects=True)
            return r.text if r.status_code == 200 else None
        req = Request(url, headers=headers)
        with urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", errors="ignore")
    except Exception:
        return None


def http_get_json(url: str, timeout: int = HTTP_TIMEOUT,
                  via_tor: bool = False) -> Optional[Dict]:
    text = http_get(url, timeout=timeout, via_tor=via_tor)
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


# ============== Scanner ==============
class DarkWebScanner:
    """Passive Dark Web reconnaissance."""

    def __init__(self):
        self.results: Dict = {
            "module": "darkweb",
            "version": "1.0",
            "timestamp": datetime.now().isoformat(),
            "tor_available": False,
            "target": None,
            "checks": {},
        }

    # ---------- Tor ----------
    def check_tor(self) -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((TOR_HOST, TOR_PORT))
            s.close()
            self.results["tor_available"] = True
            return True
        except Exception:
            self.results["tor_available"] = False
            return False

    # ---------- .onion resolve + banner ----------
    def resolve_onion(self, onion: str, port: int = 80,
                      timeout: float = ONION_TIMEOUT) -> Dict:
        out = {"onion": onion, "port": port, "reachable": False,
               "banner": None, "error": None}
        if not SOCKS_AVAILABLE:
            out["error"] = "pysocks not installed (pip install pysocks)"
            return out
        if not re.match(r"^[a-z2-7]{16}\.onion$|^[a-z2-7]{56}\.onion$", onion, re.I):
            out["error"] = "Invalid .onion address (v2 16-char or v3 56-char)"
            return out
        try:
            s = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
            s.set_proxy(socks.SOCKS5, TOR_HOST, TOR_PORT, rdns=True)
            s.settimeout(timeout)
            s.connect((onion, port))
            out["reachable"] = True
            try:
                req = (b"HEAD / HTTP/1.0\r\nHost: " + onion.encode() +
                       b"\r\nUser-Agent: " + UA.encode() + b"\r\n\r\n")
                s.send(req)
                data = s.recv(512)
                if data:
                    out["banner"] = data.decode("utf-8", errors="ignore").strip()[:300]
            except Exception:
                pass
            s.close()
        except socket.timeout:
            out["error"] = "timeout"
        except Exception as e:
            out["error"] = str(e)
        return out

    # ---------- Ahmia search ----------
    def search_ahmia(self, query: str, limit: int = 10) -> List[Dict]:
        hits: List[Dict] = []
        if not query.strip():
            return hits
        url = f"https://ahmia.fi/api/v1/search/?q={urllib.parse.quote(query)}"
        data = http_get_json(url, timeout=HTTP_TIMEOUT)
        # Ahmia returns a list, or a dict-wrapped list in some versions
        items = data if isinstance(data, list) else (
            data.get("results", []) if isinstance(data, dict) else [])
        for item in items[:limit]:
            hits.append({
                "onion": item.get("onion", ""),
                "title": item.get("title", ""),
                "description": (item.get("description") or "")[:200],
                "last_seen": item.get("lastSeen", ""),
                "category": item.get("category", ""),
            })
        return hits

    # ---------- PGP lookup ----------
    def pgp_lookup(self, query: str) -> List[Dict]:
        keys: List[Dict] = []
        if "@" in query:
            url = f"https://keys.openpgp.org/vks/v1/by-email/{urllib.parse.quote(query)}"
        else:
            url = f"https://keys.openpgp.org/vks/v1/search?q={urllib.parse.quote(query)}"
        body = http_get(url, timeout=HTTP_TIMEOUT)
        if not body:
            return keys
        pattern = (r"-----BEGIN PGP PUBLIC KEY BLOCK-----(.*?)"
                   r"-----END PGP PUBLIC KEY BLOCK-----")
        for m in re.finditer(pattern, body, re.DOTALL):
            block = m.group(0)
            uid_match = re.search(r"^uid:(.*)$", block, re.MULTILINE)
            kid_match = re.search(r"Key-ID:\s*([0-9A-Fa-f]+)", block)
            created_match = re.search(r"^pub\s+\S+\s+(\d{4}-\d{2}-\d{2})",
                                      block, re.MULTILINE)
            keys.append({
                "uid": uid_match.group(1).strip() if uid_match else "",
                "key_id": kid_match.group(1) if kid_match else "",
                "created": created_match.group(1) if created_match else "",
                "size_bytes": len(block),
            })
        return keys

    # ---------- BTC report ----------
    BTC_RE = re.compile(
        r"^[a-km-zA-HJ-NP-Z1-9]{25,34}$|^bc1[a-z0-9]{39,59}$")

    def btc_report(self, address: str) -> Dict:
        out = {"address": address, "valid": False}
        if not self.BTC_RE.match(address):
            out["error"] = "Invalid BTC address format"
            return out
        out["valid"] = True
        url = f"https://blockchain.info/rawaddr/{address}"
        data = http_get_json(url, timeout=HTTP_TIMEOUT)
        if data:
            out["balance_btc"] = data.get("final_balance", 0) / 1e8
            out["total_received_btc"] = data.get("total_received", 0) / 1e8
            out["total_sent_btc"] = data.get("total_sent", 0) / 1e8
            out["tx_count"] = data.get("n_tx", 0)
            out["first_seen"] = (data.get("txs", [{}])[-1].get("time")
                                 if data.get("txs") else None)
        else:
            out["error"] = "fetch failed"
        return out

    # ---------- Leak / reputation (emailrep.io, free) ----------
    def check_leaks(self, target: str) -> Dict:
        kind = "email" if "@" in target else "domain"
        out = {"target": target, "type": kind, "sources": {}}
        try:
            url = f"https://emailrep.io/{urllib.parse.quote(target)}"
            headers = {"User-Agent": UA, "Accept": "application/json"}
            if REQUESTS_AVAILABLE:
                r = requests.get(url, headers=headers, timeout=10)
                if r.status_code == 200:
                    out["sources"]["emailrep"] = r.json()
                else:
                    out["sources"]["emailrep"] = {"error": f"HTTP {r.status_code}"}
            else:
                req = Request(url, headers=headers)
                with urlopen(req, timeout=10) as resp:
                    out["sources"]["emailrep"] = json.loads(
                        resp.read().decode("utf-8", errors="ignore"))
        except HTTPError as e:
            out["sources"]["emailrep"] = {"error": f"HTTP {e.code}"}
        except Exception as e:
            out["sources"]["emailrep"] = {"error": str(e)}
        return out

    # ---------- Save ----------
    def save_json(self, filename: Optional[str] = None) -> str:
        if not filename:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            tgt = re.sub(r"[^A-Za-z0-9._-]", "_", (self.results.get("target") or "scan"))[:40]
            filename = os.path.join(REPORT_DIR, f"SS-darkweb-{tgt}-{ts}.json")
        with open(filename, "w") as f:
            json.dump(self.results, f, indent=2, default=str)
        return filename


# ============== Interactive menu ==============
def _safe_input(prompt: str, default: str = "") -> str:
    try:
        v = input(prompt).strip()
        return v if v else default
    except (EOFError, KeyboardInterrupt):
        return default


def _hdr(title: str):
    print(f"\n{'=' * 60}\n  {title}\n{'=' * 60}")


def _fmt_emailrep(er: Dict) -> str:
    if not er:
        return "no data"
    if "error" in er:
        return f"error: {er['error']}"
    det = er.get("details", {}) or {}
    return (
        f"reputation={er.get('reputation')}  "
        f"suspicious={er.get('suspicious')}  "
        f"blacklisted={det.get('blacklisted')}  "
        f"breach={det.get('data_breach')}  "
        f"disposable={det.get('disposable')}"
    )


def run_darkweb_menu():
    print("\n" + "=" * 60)
    print("       DARK WEB RECON MODULE  (passive / ethical)")
    print("=" * 60)
    print("[*] Clearnet APIs work without Tor.")
    print("[*] .onion ops require Tor running on 127.0.0.1:9050")
    print("[*] No marketplace interaction, no illegal content.")
    if not SOCKS_AVAILABLE:
        print("[!] 'pysocks' missing -> install: pip install pysocks")

    scanner = DarkWebScanner()
    target = _safe_input("Target (email / domain / keyword / BTC / .onion): ")
    if not target:
        print("Target required.")
        return
    scanner.results["target"] = target

    is_btc = bool(DarkWebScanner.BTC_RE.match(target))
    is_onion = target.lower().endswith(".onion")

    while True:
        print(f"\n--- DARK WEB  (target: {target}) ---")
        print(" 1. Tor status")
        print(" 2. Ahmia search (dark web search engine)")
        print(" 3. PGP key lookup")
        print(" 4. Email/Domain leak & reputation")
        print(" 5. BTC address report" + ("  (auto)" if is_btc else ""))
        print(" 6. .onion resolve + banner" + ("  (auto)" if is_onion else ""))
        print(" 7. Run ALL passive checks")
        print(" 8. Save JSON report")
        print(" 9. Back (auto-save)")

        c = _safe_input("> ")

        if c == "1":
            _hdr("TOR STATUS")
            ok = scanner.check_tor()
            print(f"{TOR_HOST}:{TOR_PORT} -> "
                  f"{'REACHABLE' if ok else 'NOT REACHABLE'}")

        elif c == "2":
            q = _safe_input("Query", target)
            _hdr(f"AHMIA SEARCH: {q}")
            hits = scanner.search_ahmia(q)
            scanner.results["checks"]["ahmia"] = {"query": q, "hits": hits}
            if not hits:
                print("[-] No results.")
            for h in hits:
                print(f" • {h['onion']}")
                print(f"   title:   {h['title']}")
                if h["description"]:
                    print(f"   desc:    {h['description']}")
                if h["last_seen"]:
                    print(f"   seen:    {h['last_seen']}")
                print()

        elif c == "3":
            _hdr(f"PGP LOOKUP: {target}")
            keys = scanner.pgp_lookup(target)
            scanner.results["checks"]["pgp"] = keys
            if not keys:
                print("[-] No keys found.")
            for k in keys:
                print(f"  UID:   {k['uid']}")
                print(f"  ID:    {k['key_id']}")
                print(f"  Date:  {k['created']}")
                print(f"  Size:  {k['size_bytes']} bytes\n")

        elif c == "4":
            _hdr(f"LEAK / REPUTATION: {target}")
            data = scanner.check_leaks(target)
            scanner.results["checks"]["leaks"] = data
            er = data.get("sources", {}).get("emailrep", {})
            print(f"  emailrep.io: {_fmt_emailrep(er)}")

        elif c == "5":
            addr = target if is_btc else _safe_input("BTC address")
            _hdr(f"BTC REPORT: {addr}")
            data = scanner.btc_report(addr)
            scanner.results["checks"]["btc"] = data
            if not data.get("valid"):
                print(f"[-] {data.get('error')}")
            else:
                print(f"  balance:    {data.get('balance_btc', 0):.8f} BTC")
                print(f"  received:   {data.get('total_received_btc', 0):.8f} BTC")
                print(f"  sent:       {data.get('total_sent_btc', 0):.8f} BTC")
                print(f"  tx count:   {data.get('tx_count', 0)}")

        elif c == "6":
            onion = target if is_onion else _safe_input(".onion address")
            port = int(_safe_input("Port", "80") or "80")
            _hdr(f"HIDDEN SERVICE: {onion}:{port}")
            if not scanner.check_tor():
                print("[-] Tor not running.")
            else:
                data = scanner.resolve_onion(onion, port)
                scanner.results["checks"]["onion"] = data
                if data.get("reachable"):
                    print("[+] Reachable")
                    if data.get("banner"):
                        print(f"    banner: {data['banner'][:300]}")
                else:
                    print(f"[-] Not reachable: {data.get('error')}")

        elif c == "7":
            _hdr("RUN ALL PASSIVE CHECKS")
            ok = scanner.check_tor()
            print(f"[{'+' if ok else '-'}] Tor: {'OK' if ok else 'no'}")

            hits = scanner.search_ahmia(target)
            scanner.results["checks"]["ahmia"] = {"query": target, "hits": hits}
            print(f"[+] Ahmia: {len(hits)} hit(s)")

            keys = scanner.pgp_lookup(target)
            scanner.results["checks"]["pgp"] = keys
            print(f"[+] PGP:   {len(keys)} key(s)")

            if "@" in target or ("." in target and " " not in target):
                leaks = scanner.check_leaks(target)
                scanner.results["checks"]["leaks"] = leaks
                er = leaks.get("sources", {}).get("emailrep", {})
                print(f"[+] Reputation: {_fmt_emailrep(er)}")

            if is_btc:
                btc = scanner.btc_report(target)
                scanner.results["checks"]["btc"] = btc
                print(f"[+] BTC: tx={btc.get('tx_count', 0)} "
                      f"bal={btc.get('balance_btc', 0):.8f}")

        elif c == "8":
            path = scanner.save_json()
            print(f"[+] Saved: {path}")

        elif c == "9":
            path = scanner.save_json()
            print(f"[*] Auto-saved: {path}")
            break

        else:
            print("Invalid option.")


if __name__ == "__main__":
    run_darkweb_menu()