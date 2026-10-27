#!/usr/bin/env python3
"""Defensive HTTP diagnostics for authorized assessment of CVE-2026-115560.

This tool does not exploit the CVE, execute commands, or prove RCE.
External HTTP responses cannot reliably establish PHP session configuration.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
from requests.exceptions import RequestException, SSLError, Timeout

TOOL_NAME = "cve_checker"
TOOL_VERSION = "1.1.0"
DEFAULT_TIMEOUT = 15
DEFAULT_RETRIES = 1
MAX_BODY_CHARS = 300

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(TOOL_NAME)


def validate_url(value: str) -> bool:
    """Accept only absolute HTTP(S) URLs with a hostname."""
    try:
        parsed = urlparse(value)
        return parsed.scheme in ("http", "https") and bool(parsed.hostname)
    except ValueError:
        return False


def same_origin(base_url: str, candidate_url: str) -> bool:
    """Return True when scheme, hostname, and effective port match."""
    try:
        a, b = urlparse(base_url), urlparse(candidate_url)
        if not (a.hostname and b.hostname):
            return False
        def port(parsed):
            return parsed.port or (443 if parsed.scheme == "https" else 80)
        return (
            a.scheme.lower() == b.scheme.lower()
            and a.hostname.lower() == b.hostname.lower()
            and port(a) == port(b)
        )
    except ValueError:
        return False


def safe_headers(headers: Any) -> dict[str, str]:
    """Return response headers while redacting common secret-bearing headers."""
    hidden = {"set-cookie", "cookie", "authorization", "proxy-authorization", "x-api-key"}
    result: dict[str, str] = {}
    for key, value in dict(headers or {}).items():
        result[str(key)] = "[REDACTED]" if str(key).lower() in hidden else str(value)
    return result


def request_with_retries(
    session: requests.Session, method: str, url: str, timeout: int, retries: int
) -> tuple[requests.Response | None, str | None]:
    last_error = None
    for attempt in range(retries + 1):
        try:
            response = session.request(
                method, url, timeout=timeout, allow_redirects=False
            )
            return response, None
        except Timeout:
            last_error = f"Timeout after {timeout} seconds"
        except SSLError as exc:
            last_error = f"TLS/SSL error: {exc}"
            break
        except RequestException as exc:
            last_error = f"Request error: {exc}"
        if attempt < retries:
            log.warning("%s; retrying (%d/%d)", last_error, attempt + 1, retries)
    return None, last_error or "Unknown request error"


def check_http(
    session: requests.Session, url: str, timeout: int, retries: int
) -> dict[str, Any]:
    started = time.monotonic()
    response, error = request_with_retries(session, "GET", url, timeout, retries)
    result: dict[str, Any] = {
        "url": url,
        "status_code": None,
        "reason": None,
        "headers": {},
        "body_snippet": "",
        "php_indicated": False,
        "duration_ms": round((time.monotonic() - started) * 1000, 2),
        "error": error,
    }
    if response is None:
        return result

    body = response.text or ""
    result.update({
        "status_code": response.status_code,
        "reason": response.reason,
        "headers": safe_headers(response.headers),
        "body_snippet": " ".join(body[:MAX_BODY_CHARS].split()),
        "php_indicated": any(
            "php" in str(value).lower()
            for key, value in response.headers.items()
            if key.lower() in {"server", "x-powered-by"}
        ),
    })
    return result


def assess_cve(http_result: dict[str, Any]) -> tuple[str, list[str]]:
    """Assess only what external HTTP evidence supports; never assert vulnerability."""
    if http_result.get("error"):
        return "ERROR", [str(http_result["error"])]

    notes = [
        "Respons HTTP tidak dapat membuktikan atau menyingkirkan CVE ini.",
        "Verifikasi konfigurasi PHP dan source code melalui akses administrator yang sah.",
        "Periksa session.serialize_handler, perubahan via ini_set() sebelum session_start(), "
        "dan session.upload_progress.enabled.",
    ]
    if http_result.get("php_indicated"):
        return "NOT_ASSESSED", notes
    notes.insert(0, "Tidak ada indikasi PHP pada header yang diperiksa; ini bukan bukti bahwa PHP tidak digunakan.")
    return "NOT_ASSESSED", notes


def build_report(url: str, result: dict[str, Any], status: str, notes: list[str]) -> dict[str, Any]:
    return {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "target": url,
        "status": status,
        "http_diagnostics": result,
        "notes": notes,
        "limitations": [
            "Tool ini tidak mengeksploitasi CVE dan tidak menguji eksekusi perintah.",
            "HTTP status, banner, dan respons halaman tidak membuktikan kondisi konfigurasi server.",
        ],
        "recommendations": [
            "Periksa advisori resmi PHP untuk status patch terbaru.",
            "Audit konfigurasi PHP dan source code dengan akses administrator yang sah.",
            "Pertimbangkan menonaktifkan session.upload_progress.enabled sesuai advisori resmi dan uji perubahan terlebih dahulu.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Pemeriksaan HTTP defensif untuk assessment CVE-2026-115560; bukan exploit."
    )
    parser.add_argument("--url", required=True, help="URL HTTP(S) milik Anda atau yang Anda berwenang uji.")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Timeout detik (1-300).")
    parser.add_argument("--retries", type=int, default=DEFAULT_RETRIES, help="Retry tambahan (0-5).")
    parser.add_argument("--output", default="cve_report.json", help="Path keluaran laporan JSON.")
    args = parser.parse_args()

    if not validate_url(args.url):
        parser.error("--url harus berupa URL absolut http:// atau https:// yang valid")
    if not 1 <= args.timeout <= 300:
        parser.error("--timeout harus antara 1 dan 300")
    if not 0 <= args.retries <= 5:
        parser.error("--retries harus antara 0 dan 5")

    session = requests.Session()
    session.headers.update({"User-Agent": f"{TOOL_NAME}/{TOOL_VERSION} (defensive diagnostics)"})
    result = check_http(session, args.url, args.timeout, args.retries)
    status, notes = assess_cve(result)
    report = build_report(args.url, result, status, notes)

    print(f"\n{TOOL_NAME} v{TOOL_VERSION}")
    print(f"Target       : {args.url}")
    print(f"HTTP status  : {result['status_code']}")
    print(f"Durasi       : {result['duration_ms']} ms")
    print(f"Indikasi PHP : {'Ya' if result['php_indicated'] else 'Tidak terdeteksi'}")
    print(f"Status CVE   : {status}")
    for note in notes:
        print(f"- {note}")

    try:
        Path(args.output).write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"Laporan JSON : {args.output}")
    except OSError as exc:
        print(f"Gagal menulis laporan: {exc}", file=sys.stderr)
        return 1
    return 1 if status == "ERROR" else 0


if __name__ == "__main__":
    raise SystemExit(main())
