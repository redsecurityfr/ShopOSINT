#!/usr/bin/env python3
"""
ShopOSINT - Payment link OSINT tool
Silently resolves a Stripe / SumUp / Revolut / Lydia link into merchant & identity
data: name, email, phone, website, product, amount, IBAN, revtag.
"""

import re
import os
import sys
import json
import base64
import colorsys
import argparse
import urllib.parse
from datetime import datetime

try:
    from curl_cffi import requests
except ImportError as e:
    print(f"[!] Missing module: {e}")
    print("[*] Install dependencies: pip install -r requirements.txt")
    sys.exit(1)


# ============================================================================
#                              TERMINAL COLORS
# ============================================================================
class Colors:
    """Terminal colors"""
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"

    DARK_RED = "\033[31m"
    DARK_GREEN = "\033[32m"
    DARK_YELLOW = "\033[33m"
    DARK_BLUE = "\033[34m"
    DARK_MAGENTA = "\033[35m"
    DARK_CYAN = "\033[36m"

    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    BLINK = "\033[5m"

    RESET = "\033[0m"

    SUCCESS = GREEN + BOLD
    ERROR = RED + BOLD
    WARNING = YELLOW + BOLD
    INFO = CYAN + BOLD
    HEADER = MAGENTA + BOLD
    TITLE = GREEN + BOLD


# ============================================================================
#                                  BANNER
# ============================================================================
ART = [
    "███████╗██╗  ██╗ ██████╗ ██████╗  ██████╗ ███████╗██╗███╗   ██╗████████╗",
    "██╔════╝██║  ██║██╔═══██╗██╔══██╗██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝",
    "███████╗███████║██║   ██║██████╔╝██║   ██║███████╗██║██╔██╗ ██║   ██║",
    "╚════██║██╔══██║██║   ██║██╔═══╝ ██║   ██║╚════██║██║██║╚██╗██║   ██║",
    "███████║██║  ██║╚██████╔╝██║     ╚██████╔╝███████║██║██║ ╚████║   ██║",
    "╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝      ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝",
]


def _rainbow(line: str, phase: float = 0.0, freq: float = 0.022) -> str:
    """Apply a truecolor rainbow gradient, column by column."""
    out = []
    last = None
    for i, ch in enumerate(line):
        if ch == ' ':
            out.append(ch)
            continue
        hue = (i * freq + phase) % 1.0
        r, g, b = (int(c * 255) for c in colorsys.hsv_to_rgb(hue, 0.85, 1.0))
        code = (r, g, b)
        if code != last:
            out.append(f"\033[1;38;2;{r};{g};{b}m")
            last = code
        out.append(ch)
    out.append(Colors.RESET)
    return "".join(out)


def print_banner():
    """Print the ShopOSINT banner (multicolor diagonal gradient)"""
    art = "\n".join(_rainbow(row, phase=idx * 0.07) for idx, row in enumerate(ART))
    banner = f"""
{art}
{Colors.CYAN}      Payment Link OSINT  ·  {Colors.MAGENTA}Stripe{Colors.CYAN} · {Colors.BLUE}SumUp{Colors.CYAN} · {Colors.GREEN}Revolut{Colors.CYAN} · {Colors.YELLOW}Lydia{Colors.RESET}
{Colors.YELLOW}+{'='*74}+
{Colors.YELLOW}|  {Colors.GREEN}\x1b]8;;https://x.com/RedSecurityfr\x1b\\@RedSecurityfr\x1b]8;;\x1b\\{Colors.YELLOW} - {Colors.GREEN}\x1b]8;;https://red-security.fr\x1b\\red-security.fr\x1b]8;;\x1b\\{Colors.YELLOW} - {Colors.GREEN}\x1b]8;;https://osint-opsec.fr\x1b\\osint-opsec.fr\x1b]8;;\x1b\\{Colors.YELLOW} - {Colors.GREEN}\x1b]8;;https://roso.info\x1b\\roso.info\x1b]8;;\x1b\\{Colors.YELLOW}           |
{Colors.YELLOW}|{' '*74}|
{Colors.YELLOW}|  {Colors.RED}Join the OSINT community:{Colors.YELLOW}{' '*47}|
{Colors.YELLOW}|  {Colors.GREEN}\x1b]8;;https://discord.com/invite/rPkY5jaTfF\x1b\\https://discord.com/invite/rPkY5jaTfF\x1b]8;;\x1b\\{Colors.YELLOW}{' '*35}|
{Colors.YELLOW}+{'='*74}+{Colors.RESET}
"""
    print(banner)


# ============================================================================
#                                 CONSTANTS
# ============================================================================
IMPERSONATE = "chrome124"
TIMEOUT = 25

STRIPE_CS_RE = re.compile(r"(cs_(?:live|test)_[A-Za-z0-9]+)")
SUMUP_CODE_RE = re.compile(r"pay\.sumup\.com/b2c/([A-Za-z0-9]+)", re.I)
REVOLUT_TAG_RE = re.compile(r"revolut\.me/([A-Za-z0-9_.-]+)", re.I)
LYDIA_COLLECT_RE = re.compile(r"pots\.lydia\.me/collect/([^/?#]+)", re.I)
UUID_RE = re.compile(r'checkout_id"\s*:\s*"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"', re.I)
PK_RE = re.compile(r"pk_(?:live|test)_[A-Za-z0-9]+")

PROVIDER_LABELS = {
    'stripe': 'Stripe', 'sumup': 'SumUp', 'revolut': 'Revolut', 'lydia': 'Lydia',
}


def _norm(s):
    if s is None:
        return None
    s = str(s).strip()
    return s or None


# ============================================================================
#                                MAIN CLASS
# ============================================================================
class ShopOSINT:
    """Payment link resolver (Stripe / SumUp / Revolut / Lydia)"""

    def __init__(self, url: str, verbose: bool = False):
        self.url = self._clean_url(url)
        self.verbose = verbose
        self.provider = self.detect_provider(self.url)
        self.result = None
        self.results = {
            'url': self.url,
            'scan_date': datetime.now().isoformat(),
            'provider': self.provider,
            'data': None,
        }

    # ---- helpers --------------------------------------------------------
    def _clean_url(self, url: str) -> str:
        url = (url or "").strip()
        if not re.match(r"^https?://", url, re.I):
            url = "https://" + url
        return url

    def _log(self, message: str, color: str = Colors.WHITE):
        if self.verbose:
            print(f"{color}[*] {message}{Colors.RESET}")

    @staticmethod
    def detect_provider(url: str):
        u = (url or "").lower()
        if "stripe.com" in u:
            return "stripe"
        if "sumup.com" in u:
            return "sumup"
        if "revolut.me" in u:
            return "revolut"
        if "pots.lydia.me" in u or "lydia.me/collect" in u:
            return "lydia"
        return None

    @staticmethod
    def _err(code: str, detail: str) -> dict:
        return {"ok": False, "error": code, "detail": detail}

    # ====================================================================
    #                              STRIPE
    # ====================================================================
    @staticmethod
    def _xor5(b: bytes) -> str:
        return "".join(chr(5 ^ c) for c in b)

    def _decode_stripe_fragment(self, fragment: str):
        if fragment.startswith("#"):
            fragment = fragment[1:]
        ud = urllib.parse.unquote(fragment)
        if not ud:
            return None
        try:
            return json.loads(self._xor5(base64.b64decode(ud + "=" * (-len(ud) % 4))))
        except Exception:
            return None

    def _stripe_key_and_cs(self, url: str):
        parsed = urllib.parse.urlsplit(url.strip())
        if parsed.fragment:
            meta = self._decode_stripe_fragment(parsed.fragment)
            if meta and meta.get("apiKey"):
                m = STRIPE_CS_RE.search(parsed.path) or STRIPE_CS_RE.search(url)
                if m:
                    self._log("Publishable key extracted from #fid fragment", Colors.DARK_CYAN)
                    return meta["apiKey"], m.group(1), None
        self._log(f"Loading Stripe page: {url[:60]}...", Colors.DARK_CYAN)
        try:
            r = requests.get(url, impersonate=IMPERSONATE, timeout=TIMEOUT, allow_redirects=True)
        except Exception as e:
            return None, None, self._err("fetch_failed", f"could not load Stripe URL: {e}")
        cs_m = STRIPE_CS_RE.search(str(r.url)) or STRIPE_CS_RE.search(r.text)
        key_m = PK_RE.search(r.text)
        if cs_m and key_m:
            return key_m.group(0), cs_m.group(1), None
        if cs_m:
            return None, cs_m.group(1), self._err(
                "no_key",
                "session found but the publishable key is in the URL fragment — "
                "paste the full checkout.stripe.com/c/pay/... link including the #fid... part")
        return None, None, self._err("bad_url", "no Stripe checkout session found at this URL")

    def resolve_stripe(self) -> dict:
        api_key, cs_id, err = self._stripe_key_and_cs(self.url)
        if err:
            return err
        self._log("Replaying POST /init (silent, no card)", Colors.DARK_CYAN)
        body = {"key": api_key, "eid": "NA", "browser_locale": "en-US",
                "browser_timezone": "Europe/Paris", "redirect_type": "stripe_js"}
        try:
            r = requests.post(f"https://api.stripe.com/v1/payment_pages/{cs_id}/init",
                              data=body, impersonate=IMPERSONATE, timeout=TIMEOUT)
        except Exception as e:
            return self._err("fetch_failed", f"init request failed: {e}")

        if r.status_code != 200:
            low = r.text[:200].lower()
            if r.status_code == 410 or "no longer" in low or "expired" in low:
                return self._err("expired", "checkout session expired or already completed")
            if r.status_code == 404 or "resource_missing" in low:
                return self._err("not_found", "checkout session not found")
            if r.status_code == 403 and "cloudfront" in low:
                return self._err("blocked", "request blocked upstream")
            return self._err("upstream", f"Stripe init HTTP {r.status_code}")
        try:
            j = r.json()
        except Exception:
            return self._err("upstream", "Stripe init response not JSON")

        acc = j.get("account_settings", {}) or {}
        products = []

        def _items(o):
            if isinstance(o, dict):
                li = o.get("line_items")
                for it in (li if isinstance(li, list) else [li] if isinstance(li, dict) else []):
                    nm = _norm((it or {}).get("name"))
                    if nm and nm not in products:
                        products.append(nm)
                for v in o.values():
                    _items(v)
            elif isinstance(o, list):
                for it in o:
                    _items(it)

        _items(j)
        links = {k: _norm(j.get(k)) for k in ("success_url", "cancel_url") if _norm(j.get(k))}
        return {
            "ok": True, "provider": "stripe",
            "merchant_name": _norm(acc.get("display_name")) or _norm(acc.get("merchant_of_record_display_name")),
            "email": _norm(acc.get("support_email")),
            "phone": _norm(acc.get("support_phone")),
            "website": _norm(acc.get("business_url")),
            "country": _norm(acc.get("country")) or _norm(acc.get("merchant_of_record_country")),
            "product": ", ".join(products) or None,
            "amount": None, "currency": _norm(j.get("currency")),
            "links": links,
            "raw": {
                "cs_id": cs_id,
                "statement_descriptor": _norm(acc.get("statement_descriptor")) or _norm(j.get("statement_descriptor")),
                "support_url": _norm(acc.get("support_url")),
                "privacy_policy_url": _norm(acc.get("privacy_policy_url")),
                "terms_of_service_url": _norm(acc.get("terms_of_service_url")),
                "livemode": (not j.get("is_sandbox_merchant")) if "is_sandbox_merchant" in j else None,
            },
        }

    # ====================================================================
    #                              SUMUP
    # ====================================================================
    def resolve_sumup(self) -> dict:
        m = SUMUP_CODE_RE.search(self.url) or re.search(r"/b2c/([A-Za-z0-9]+)", self.url)
        if not m:
            return self._err("bad_url", "unrecognized SumUp payment link (pay.sumup.com/b2c/CODE)")
        code = m.group(1)
        link = f"https://pay.sumup.com/b2c/{code}"
        self._log(f"Loading SumUp page: {link}", Colors.DARK_CYAN)
        try:
            page = requests.get(link, impersonate=IMPERSONATE, timeout=TIMEOUT)
        except Exception as e:
            return self._err("fetch_failed", f"could not load SumUp link: {e}")
        if page.status_code != 200:
            return self._err("not_found", f"SumUp link HTTP {page.status_code}")

        t = page.text
        cm = UUID_RE.search(t)
        if not cm:
            return self._err("not_found", "no checkout for this SumUp link (expired/invalid?)")
        checkout_id = cm.group(1)

        page_name = None
        nm = re.search(r'"merchant_name"\s*:\s*"([^"]+)"', t)
        if nm:
            page_name = nm.group(1)
        cc = re.search(r'"merchant_code"\s*:\s*"([^"]+)"', t)
        page_code = cc.group(1) if cc else None
        am = re.search(r'pay\s*[€$£]?\s*([0-9]+(?:[.,][0-9]{2})?)\s+to', t, re.I)
        page_amount = am.group(1).replace(",", ".") if am else None

        hdr = {
            "Origin": "https://pay.sumup.com", "Referer": link, "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        }
        self._log("Reading checkout (creates a FAILED attempt, no charge)", Colors.DARK_YELLOW)
        try:
            r = requests.put(f"https://api.sumup.com/v0.1/checkouts/{checkout_id}",
                             headers=hdr, data=json.dumps({"payment_type": "card"}),
                             impersonate=IMPERSONATE, timeout=TIMEOUT)
        except Exception as e:
            return self._err("fetch_failed", f"checkout read failed: {e}")

        if r.status_code != 200:
            # PUT failed — fall back to the merchant data embedded in the b2c page
            # (no email, but name/amount). Decode SumUp's error to explain why.
            self._log(f"checkout PUT HTTP {r.status_code}: {r.text[:160]}", Colors.DARK_YELLOW)
            err_code, err_msg = None, None
            try:
                ej = r.json()
                err_code = ej.get("error_code")
                err_msg = ej.get("message")
            except Exception:
                pass
            reason = {
                "CHECKOUT_ATTEMPTS_EXCEEDED": "attempts exceeded — email locked (link already read too many times)",
                "CHECKOUT_NOT_FOUND": "checkout not found / expired",
            }.get(err_code)
            state = reason or err_code or f"http_{r.status_code}"
            if page_name or page_amount or page_code:
                return {
                    "ok": True, "provider": "sumup", "merchant_name": _norm(page_name),
                    "email": None, "phone": None, "website": None, "country": None,
                    "product": None, "amount": page_amount, "currency": "EUR" if page_amount else None,
                    "links": {"redirect_url": link},
                    "raw": {"checkout_id": checkout_id, "merchant_code": _norm(page_code),
                            "state": state, "error_code": err_code},
                }
            return self._err("upstream", f"SumUp checkout: {err_msg or r.text[:140]}")
        try:
            j = r.json()
        except Exception:
            return self._err("upstream", "SumUp response not JSON")

        amount = j.get("amount")
        return {
            "ok": True, "provider": "sumup",
            "merchant_name": _norm(j.get("merchant_name")) or _norm(page_name),
            "email": _norm(j.get("pay_to_email")), "phone": None, "website": None,
            "country": _norm(j.get("merchant_country")), "product": _norm(j.get("description")),
            "amount": str(amount) if amount is not None else page_amount,
            "currency": _norm(j.get("currency")),
            "links": {k: _norm(j.get(k)) for k in ("redirect_url", "return_url") if _norm(j.get(k))},
            "raw": {"checkout_id": checkout_id, "merchant_code": _norm(j.get("merchant_code")),
                    "status": _norm(j.get("status")), "purpose": _norm(j.get("purpose")),
                    "sumup_product": _norm(j.get("sumup_product"))},
        }

    # ====================================================================
    #                              REVOLUT
    # ====================================================================
    def resolve_revolut(self) -> dict:
        m = REVOLUT_TAG_RE.search(self.url)
        if not m:
            return self._err("bad_url", "invalid Revolut link (revolut.me/<revtag>)")
        tag = m.group(1).lstrip("@")
        self._log(f"GET revolut.me/api/web-profile/{tag}", Colors.DARK_CYAN)
        try:
            r = requests.get(f"https://revolut.me/api/web-profile/{tag}",
                             impersonate=IMPERSONATE, timeout=TIMEOUT,
                             headers={"Accept": "application/json", "Referer": f"https://revolut.me/{tag}"})
        except Exception as e:
            return self._err("fetch_failed", f"Revolut profile fetch failed: {e}")
        if r.status_code == 404:
            return self._err("not_found", "revtag not found")
        if r.status_code != 200 or "json" not in r.headers.get("content-type", ""):
            return self._err("upstream", f"Revolut HTTP {r.status_code}")
        try:
            j = r.json()
        except Exception:
            return self._err("upstream", "Revolut response not JSON")

        first = _norm(j.get("firstName"))
        last = _norm(j.get("lastName"))
        full = " ".join(x for x in (first, last) if x) or tag
        pm = j.get("paymentMethods") or []
        mpt = j.get("mobilePaymentTypes") or []
        extra = {}
        if pm:
            extra["Payment methods"] = ", ".join(pm)
        if mpt:
            extra["Mobile pay"] = ", ".join(mpt)
        return {
            "ok": True, "provider": "revolut", "merchant_name": full,
            "email": None, "phone": None, "username": tag,
            "website": f"https://revolut.me/{tag}", "country": _norm(j.get("country")),
            "product": None, "amount": None, "currency": _norm(j.get("baseCurrency")),
            "links": {}, "extra": extra,
            "raw": {"username": tag, "firstName": first, "lastName": last,
                    "paymentMethods": pm, "mobilePaymentTypes": mpt},
        }

    # ====================================================================
    #                              LYDIA
    # ====================================================================
    def resolve_lydia(self) -> dict:
        parsed = urllib.parse.urlsplit(self.url)
        qs = urllib.parse.parse_qs(parsed.query)
        slug = None
        for key in ("id", "slug"):
            if qs.get(key):
                slug = qs[key][0]
                break
        if not slug:
            m = LYDIA_COLLECT_RE.search(self.url)
            if m and m.group(1).lower() not in ("pots", "moneypotdata"):
                slug = m.group(1)
        if not slug:
            return self._err("bad_url", "invalid Lydia pot link (pots.lydia.me/collect/...)")
        self._log(f"GET pots.lydia.me/collect/moneypotdata?slug={slug}", Colors.DARK_CYAN)
        try:
            r = requests.get(f"https://pots.lydia.me/collect/moneypotdata?slug={slug}",
                             impersonate=IMPERSONATE, timeout=TIMEOUT, headers={"Accept": "application/json"})
        except Exception as e:
            return self._err("fetch_failed", f"Lydia moneypotdata fetch failed: {e}")
        if r.status_code != 200 or "json" not in r.headers.get("content-type", ""):
            return self._err("not_found", f"pot not found (HTTP {r.status_code})")
        try:
            j = r.json()
        except Exception:
            return self._err("upstream", "Lydia response not JSON")
        if not isinstance(j, dict) or not j:
            return self._err("not_found", "pot not found or invalid slug")

        name = _norm(j.get("collector_name"))
        iban = _norm(j.get("collectIban"))
        iban_compact = iban.replace(" ", "") if iban else None
        bic = _norm(j.get("collectBic"))
        title = _norm(j.get("title"))
        img = j.get("image_src")
        cover = img if isinstance(img, str) and img.startswith("http") else None
        total = j.get("total_collected")
        balance = j.get("balance")
        archived = bool(j.get("archived"))
        desc = _norm(j.get("description"))
        country = iban_compact[:2].upper() if iban_compact and iban_compact[:2].isalpha() else None
        if not (name or title):
            return self._err("not_found", "pot metadata not found")

        owner = _norm(j.get("owner_type"))
        owner_label = {"p2p": "Individual (P2P)", "pro": "Professional", "business": "Business"}.get(owner, owner)
        extra = {}
        if iban:
            extra["Beneficiary IBAN"] = iban
        if bic:
            extra["BIC"] = bic
        if title:
            extra["Pot title"] = title
        if desc:
            extra["Description"] = desc[:300]
        extra["Status"] = "closed / archived" if archived else "open (active donations)"
        if owner_label:
            extra["Account type"] = owner_label
        if total:
            extra["Total collected"] = f"{total} €"
        if balance and balance != total:
            extra["Balance"] = f"{balance} €"
        if cover:
            extra["Cover image"] = cover
        return {
            "ok": True, "provider": "lydia", "merchant_name": name or title,
            "email": None, "phone": None,
            "website": f"https://pots.lydia.me/collect/{slug}/fr",
            "country": country, "product": title,
            "amount": str(total) if total else None, "currency": "EUR" if total else None,
            "links": {}, "extra": extra,
            "raw": {"slug": slug, "collector_name": name, "collectIban": iban, "collectBic": bic,
                    "title": title, "cover_image": cover, "total_collected": total,
                    "balance": balance, "archived": archived, "owner_type": owner},
        }

    # ====================================================================
    #                            ORCHESTRATION
    # ====================================================================
    def run(self) -> dict:
        if not self.provider:
            self.result = self._err("unsupported", "unsupported link — Stripe, SumUp, Revolut or Lydia only")
            self.results['data'] = self.result
            return self.result

        self._log(f"Provider detected: {PROVIDER_LABELS[self.provider]}", Colors.DARK_CYAN)
        dispatch = {
            'stripe': self.resolve_stripe, 'sumup': self.resolve_sumup,
            'revolut': self.resolve_revolut, 'lydia': self.resolve_lydia,
        }
        try:
            self.result = dispatch[self.provider]()
        except Exception as e:
            self.result = self._err("internal", str(e)[:200])
        self.results['data'] = self.result
        return self.result

    # ====================================================================
    #                         OUTPUT (flat / raw)
    # ====================================================================
    def _collect_fields(self, d: dict):
        """Ordered (label, value) list of the raw data to display."""
        raw = d.get('raw') or {}
        f = []
        prov = d.get('provider') or self.provider
        f.append(("Provider", PROVIDER_LABELS.get(prov, prov)))
        if d.get('merchant_name'):
            f.append(("Name", d['merchant_name']))
        if d.get('email'):
            f.append(("Email", d['email']))
        if d.get('phone'):
            f.append(("Phone", d['phone']))
        if d.get('username'):
            f.append(("Revtag", "@" + d['username']))
        if d.get('website'):
            f.append(("Website", d['website']))
        if d.get('country'):
            f.append(("Country", d['country']))
        if d.get('product'):
            f.append(("Product", d['product']))
        if d.get('amount'):
            cur = (" " + d['currency'].upper()) if d.get('currency') else ""
            f.append(("Amount", f"{d['amount']}{cur}"))
        elif d.get('currency'):
            f.append(("Currency", d['currency'].upper()))
        if raw.get('statement_descriptor'):
            f.append(("Statement descriptor", raw['statement_descriptor']))
        if raw.get('merchant_code'):
            f.append(("Merchant code", raw['merchant_code']))
        for k, v in (d.get('extra') or {}).items():
            if v:
                f.append((k, v))
        for k, v in (d.get('links') or {}).items():
            if v:
                f.append((k.replace("_", " ").capitalize(), v))
        if raw.get('cs_id'):
            f.append(("Stripe session", raw['cs_id']))
        if raw.get('checkout_id'):
            f.append(("Checkout ID", raw['checkout_id']))
        if raw.get('slug'):
            f.append(("Slug", raw['slug']))
        if raw.get('status'):
            f.append(("Payment status", raw['status']))
        if raw.get('state') and not d.get('email'):
            f.append(("Checkout state", raw['state']))
        return f

    def print_results(self):
        d = self.result
        print(f"\n{Colors.BOLD}{Colors.YELLOW}{self.url}{Colors.RESET}\n")

        if not d or d.get('ok') is False:
            msg = (d.get('detail') or d.get('error')) if d else "no data"
            print(f"{Colors.RED}[!] Resolution failed: {msg}{Colors.RESET}")
            return

        fields = self._collect_fields(d)
        width = max((len(k) for k, _ in fields), default=0)
        for label, value in fields:
            print(f"  {Colors.CYAN}{label.ljust(width)}{Colors.RESET}  {value}")

    # ====================================================================
    #                              EXPORT
    # ====================================================================
    def _safe_id(self) -> str:
        d = self.result or {}
        raw = d.get('raw') or {}
        ident = (raw.get('cs_id') or raw.get('checkout_id') or raw.get('slug')
                 or d.get('username') or raw.get('merchant_code') or 'result')
        return re.sub(r'[^A-Za-z0-9_-]', '_', str(ident))[:40]

    def export_json(self, filename: str = None):
        if not filename:
            prov = self.provider or 'unknown'
            filename = f"shoposint_{prov}_{self._safe_id()}.json"
        clean = json.loads(json.dumps(self.results, default=str))
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(clean, f, ensure_ascii=False, indent=2)
        print(f"\n{Colors.GREEN}[+] Results exported to {filename}{Colors.RESET}")


# ============================================================================
#                                  MAIN
# ============================================================================
class _DevNull:
    """Sink stdout (used in --json mode to mute the human-readable workflow)."""
    def write(self, *_):
        return 0
    def flush(self):
        pass


def main():
    # Fix Windows console encoding
    if sys.platform == 'win32':
        try:
            import io
            sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
            sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
            os.system('chcp 65001 > nul 2>&1')
        except Exception:
            pass

    parser = argparse.ArgumentParser(
        description='ShopOSINT - Payment link OSINT tool (Stripe / SumUp / Revolut / Lydia)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Colors.CYAN}Examples:{Colors.RESET}
  python shoposint.py                                          # Interactive mode
  python shoposint.py pay.sumup.com/b2c/ABCD1234               # Resolve a SumUp link
  python shoposint.py revolut.me/johndoe -v --export          # Verbose + JSON export
  python shoposint.py "checkout.stripe.com/c/pay/cs_live_...#fid..."
  python shoposint.py pots.lydia.me/collect/my-pot
        """
    )
    parser.add_argument('url', nargs='?', help='Payment link to resolve')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose mode')
    parser.add_argument('--export', action='store_true', help='Export results to JSON')
    parser.add_argument('--json', action='store_true', help='Raw JSON output to stdout (scripting)')
    args = parser.parse_args()

    # Pure JSON mode (machine): no banner/colors, raw JSON
    if args.json:
        if not args.url:
            print(json.dumps({"ok": False, "error": "bad_url", "detail": "missing url"}))
            sys.exit(2)
        scanner = ShopOSINT(args.url, verbose=False)
        import contextlib
        with contextlib.redirect_stdout(_DevNull()):
            scanner.run()
        print(json.dumps(scanner.result, ensure_ascii=False, indent=2))
        sys.exit(0 if scanner.result.get('ok') else 1)

    print_banner()

    # Interactive mode
    if not args.url:
        print(f"\n{Colors.CYAN}Enter the link to resolve (Stripe / SumUp / Revolut / Lydia):{Colors.RESET}")
        url = input(f"{Colors.YELLOW}>{Colors.RESET} ").strip()
        if not url:
            print(f"{Colors.RED}[!] Link required{Colors.RESET}")
            sys.exit(1)
    else:
        url = args.url

    scanner = ShopOSINT(url, verbose=args.verbose)
    scanner.run()
    scanner.print_results()
    if args.export:
        scanner.export_json()


if __name__ == '__main__':
    main()
