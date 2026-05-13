#!/usr/bin/env python3
"""
FortiScan — FortiGate Vulnerability Scanner
Centrally managed, modular CLI for checking FortiGate/FortiOS CVEs.

Usage:
  python fortiscan.py --target 10.0.0.1:443 --all
  python fortiscan.py --target 10.0.0.1:443 --cve CVE-2024-21762 CVE-2023-27997
  python fortiscan.py --file targets.txt --all
  python fortiscan.py --list
  python fortiscan.py          (interactive mode)

Adding a new check:
  1. Create modules/cve_YYYY_XXXXX.py with a class extending BaseCheck
  2. Import and register it in REGISTRY below — one line
"""

import argparse
import csv
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import textwrap
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    _COLOR = True
except ImportError:
    _COLOR = False

from modules.base import CheckResult
from modules.cve_2018_13379 import CVE_2018_13379
from modules.cve_2022_40684_leak import CVE_2022_40684_Leak
from modules.cve_2022_40684 import CVE_2022_40684
from modules.cve_2023_27997 import CVE_2023_27997
from modules.cve_2024_21762 import CVE_2024_21762
from modules.cve_2024_55591 import CVE_2024_55591
from modules.cve_2025_64446 import CVE_2025_64446

# ── Registry ─────────────────────────────────────────────────────────────────
# To add a new check: import the class above and add one entry here.
REGISTRY = {
    "CVE-2018-13379":      CVE_2018_13379,
    "CVE-2022-40684-LEAK": CVE_2022_40684_Leak,
    "CVE-2022-40684":      CVE_2022_40684,
    "CVE-2023-27997":      CVE_2023_27997,
    "CVE-2024-21762":      CVE_2024_21762,
    "CVE-2024-55591":      CVE_2024_55591,
    "CVE-2025-64446":      CVE_2025_64446,
}

BANNER = r"""
  _____         _   _ _____
 |  ___|__  _ _| |_(_) ___|  ___ __ _ _ __
 | |_ / _ \| '_|  _| \__ \ / __/ _` | '_ \
 |  _| (_) | |  |_| | ___) | (_| (_| | | | |
 |_|  \___/|_|  \__|_|____/ \___\__,_|_| |_|

 FortiGate Vulnerability Scanner  |  github.com/EddieGerbs/FortiScan
"""

VERSION = "1.0.0"

_FORTI_KEYWORDS = ["fortigate", "fortinet", "forticlient", "ssl-vpn", "sslvpn", "fortios", "fortiweb"]
_FORTI_CN_PREFIXES = ("FGT", "FGVM", "FGVMK", "FW", "FORTIGATE", "FORTINET")
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


# ── Colour helpers ────────────────────────────────────────────────────────────

def _c(text: str, colour: str) -> str:
    if not _COLOR:
        return text
    return colour + text + Style.RESET_ALL


STATUS_COLOUR = {
    "VULNERABLE": Fore.RED    if _COLOR else "",
    "PATCHED":    Fore.GREEN  if _COLOR else "",
    "UNKNOWN":    Fore.YELLOW if _COLOR else "",
    "ERROR":      Fore.CYAN   if _COLOR else "",
    "NOT_FOUND":  Fore.GREEN  if _COLOR else "",
}


def _status_str(status: str) -> str:
    colour = STATUS_COLOUR.get(status, "")
    label = f"[{status:<11}]"
    return _c(label, colour) if _COLOR else label


# ── Pre-flight fingerprinting ─────────────────────────────────────────────────

def _cert_cn(host: str, port: int) -> str:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=8) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert()
                for field in cert.get("subject", []):
                    if field[0][0] == "commonName":
                        return field[0][1]
    except Exception:
        pass
    return ""


def _fingerprint_target(host: str, port: int) -> dict:
    """
    Lightweight pre-flight check: is this target a FortiGate / Fortinet device?

    Checks (in order):
      1. SSL certificate CN — FGT* serial numbers are unique to FortiGate hardware
      2. HTTP response body / page title at / and /remote/login

    Returns:
      {
        "confirmed": bool,
        "indicators": [str, ...],   # evidence that it IS FortiGate
        "concerns":  [str, ...],    # evidence that it may NOT be
      }
    """
    indicators: list = []
    concerns: list = []

    # 1. SSL cert CN
    cn = _cert_cn(host, port)
    if cn:
        if cn.upper().startswith(_FORTI_CN_PREFIXES) or any(
            k in cn.lower() for k in ("fortigate", "fortinet")
        ):
            indicators.append(f"SSL cert CN: '{cn}' (FortiGate identifier)")
        else:
            concerns.append(f"SSL cert CN: '{cn}'")

    # 2. HTTP pages
    for path in ("/remote/login", "/"):
        try:
            r = requests.get(
                f"https://{host}:{port}{path}",
                verify=False, timeout=8, allow_redirects=True,
            )
            body_lower = r.text.lower()
            title_m = _TITLE_RE.search(r.text)
            title = title_m.group(1).strip() if title_m else ""

            found_kw = [k for k in _FORTI_KEYWORDS if k in body_lower]
            if found_kw:
                note = f"Page at {path}"
                if title:
                    note += f" (title: '{title}')"
                note += f" — contains: {', '.join(found_kw)}"
                indicators.append(note)
                break  # One confirmed hit is enough
            elif title:
                concerns.append(f"Page at {path} — title: '{title}', no FortiGate keywords found")
        except Exception:
            pass

    return {
        "confirmed": len(indicators) > 0,
        "indicators": indicators,
        "concerns": concerns,
    }


def _run_preflight(targets: List[Tuple[str, int]], skip: bool) -> bool:
    """
    Fingerprint each unique target. Warn if any don't look like FortiGate.
    Returns False if the user chose to abort, True to continue.
    """
    if skip:
        return True

    unique = list(dict.fromkeys(targets))  # deduplicate, preserve order
    print(_c("  Pre-flight target verification", Fore.CYAN if _COLOR else ""))
    print("  " + "─" * 60)

    unconfirmed = []
    for host, port in unique:
        tgt = f"{host}:{port}"
        fp = _fingerprint_target(host, port)
        if fp["confirmed"]:
            print(_c(f"  [+] {tgt}", Fore.GREEN if _COLOR else ""))
            for note in fp["indicators"]:
                print(f"        {note}")
        else:
            print(_c(f"  [?] {tgt} — does not appear to be a FortiGate device", Fore.YELLOW if _COLOR else ""))
            if fp["concerns"]:
                for note in fp["concerns"]:
                    print(f"        {note}")
            else:
                print( "        No FortiGate indicators found in certificate, page title, or response body")
            unconfirmed.append(tgt)

    print()

    if not unconfirmed:
        return True

    # Prompt only when stdin is a real terminal; skip prompt in piped/automated use
    if sys.stdin.isatty():
        targets_str = ", ".join(unconfirmed)
        prompt = _c(
            f"  The following target(s) could not be confirmed as FortiGate devices: {targets_str}\n"
            f"  Continuing may produce inaccurate results.\n"
            f"  Proceed anyway? [y/N]: ",
            Fore.YELLOW if _COLOR else "",
        )
        try:
            answer = input(prompt).strip().lower()
        except (KeyboardInterrupt, EOFError):
            print()
            return False
        if answer != "y":
            print(_c("  Scan cancelled.", Fore.RED if _COLOR else ""))
            return False
    else:
        print(_c(
            f"  [!] Unconfirmed target(s): {', '.join(unconfirmed)} — proceeding in non-interactive mode",
            Fore.YELLOW if _COLOR else "",
        ))

    return True


# ── Target parsing ────────────────────────────────────────────────────────────

def _parse_target(raw: str) -> Tuple[str, int]:
    """Parse 'host:port' or 'host' (defaults port 443) into (host, port)."""
    raw = raw.strip()
    if not raw:
        raise ValueError("Empty target string")
    if raw.startswith("["):
        bracket_end = raw.find("]")
        if bracket_end == -1:
            raise ValueError(f"Malformed IPv6 address: {raw}")
        host = raw[1:bracket_end]
        rest = raw[bracket_end + 1:]
        port = int(rest.lstrip(":")) if ":" in rest else 443
        return host, port
    if raw.count(":") == 1:
        host, port_str = raw.rsplit(":", 1)
        return host, int(port_str)
    return raw, 443


def _load_targets_file(path: str) -> List[Tuple[str, int]]:
    targets = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                targets.append(_parse_target(line))
            except ValueError as e:
                print(_c(f"  [!] Skipping invalid target '{line}': {e}", Fore.YELLOW if _COLOR else ""))
    return targets


# ── Output / reporting ────────────────────────────────────────────────────────

def _print_result(r: CheckResult) -> None:
    cve_col = _c(f"{r.cve:<22}", Fore.CYAN if _COLOR else "")
    tgt_col = _c(f"{r.target:<22}", Fore.WHITE if _COLOR else "")
    print(f"  {_status_str(r.status)}  {cve_col}  {tgt_col}  {r.detail}")

    if r.data.get("credentials"):
        for cred in r.data["credentials"]:
            print(
                "    " + _c("CRED", Fore.MAGENTA if _COLOR else "")
                + f"  user={cred['username']}  pass={cred['password']}"
                + f"  group={cred['group']}  ext_ip={cred['ext_ip']}"
            )


def _save_json(results: List[CheckResult], path: str) -> None:
    data = [
        {"cve": r.cve, "target": r.target, "status": r.status,
         "detail": r.detail, "data": r.data}
        for r in results
    ]
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)


def _save_csv(results: List[CheckResult], path: str) -> None:
    with open(path, "w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["CVE", "Target", "Status", "Detail"])
        for r in results:
            writer.writerow([r.cve, r.target, r.status, r.detail])


# ── Check runner ──────────────────────────────────────────────────────────────

def _run_checks(
    targets: List[Tuple[str, int]],
    check_ids: List[str],
    dump_creds: bool = False,
    threads: int = 10,
) -> List[CheckResult]:
    tasks = [(host, port, cid) for (host, port) in targets for cid in check_ids]
    results: List[CheckResult] = []

    def _execute(host, port, cid):
        checker = REGISTRY[cid]()
        kwargs = {"dump_creds": dump_creds} if cid == "CVE-2018-13379" else {}
        return checker.run(host, port, **kwargs)

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(_execute, h, p, cid): (h, p, cid) for h, p, cid in tasks}
        for future in as_completed(futures):
            result = future.result()
            _print_result(result)
            results.append(result)

    return results


# ── List checks ───────────────────────────────────────────────────────────────

def _list_checks() -> None:
    print(_c("\nAvailable checks:\n", Fore.CYAN if _COLOR else ""))
    header = f"  {'CVE ID':<24}  {'Description':<52}  Affected versions"
    print(_c(header, Fore.WHITE if _COLOR else ""))
    print("  " + "─" * 110)
    for cid, cls in REGISTRY.items():
        info = cls.info()
        desc = textwrap.shorten(info["description"], 52)
        affected = textwrap.shorten(info["affected"], 40)
        print(f"  {_c(cid, Fore.YELLOW if _COLOR else ''):<24}  {desc:<52}  {affected}")
    print()


# ── Interactive mode ──────────────────────────────────────────────────────────

def _prompt(msg: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    try:
        val = input(_c(f"  {msg}{suffix}: ", Fore.CYAN if _COLOR else "")).strip()
    except (KeyboardInterrupt, EOFError):
        print()
        sys.exit(0)
    return val if val else default


def _interactive() -> argparse.Namespace:
    print(_c("\n  No target specified — entering interactive mode\n", Fore.YELLOW if _COLOR else ""))
    _list_checks()

    target_raw = _prompt("Target (host:port or host)")
    while not target_raw:
        print(_c("  Target is required.", Fore.RED if _COLOR else ""))
        target_raw = _prompt("Target (host:port or host)")

    check_input = _prompt("CVE IDs to run (comma-separated, or 'all')", "all")
    dump = _prompt("Enable credential dump for CVE-2018-13379? (y/N)", "n").lower() == "y"
    threads_str = _prompt("Concurrent threads", "10")
    skip_verify = _prompt("Skip pre-flight target verification? (y/N)", "n").lower() == "y"

    ns = argparse.Namespace()
    ns.target = [target_raw]
    ns.file = None
    ns.all = check_input.strip().lower() == "all"
    ns.cve = (
        None if ns.all
        else [c.strip().upper() for c in check_input.split(",") if c.strip()]
    )
    ns.dump_creds = dump
    ns.threads = int(threads_str) if threads_str.isdigit() else 10
    ns.output = None
    ns.format = "table"
    ns.no_color = False
    ns.skip_verify = skip_verify
    return ns


# ── Argument parser ───────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="fortiscan",
        description="FortiGate vulnerability scanner — checks multiple CVEs against one or more targets.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        examples:
          python fortiscan.py --target 10.0.0.1:443 --all
          python fortiscan.py --target 10.0.0.1:10443 --cve CVE-2024-21762 CVE-2023-27997
          python fortiscan.py --file targets.txt --all --output results.json --format json
          python fortiscan.py --list
        """),
    )
    p.add_argument("--version", action="version", version=f"FortiScan {VERSION}")
    p.add_argument("--list", action="store_true", help="List all available CVE checks and exit")

    target_group = p.add_argument_group("target specification")
    target_group.add_argument(
        "--target", metavar="HOST:PORT", nargs="+",
        help="One or more targets in host:port format (port defaults to 443)",
    )
    target_group.add_argument(
        "--file", metavar="FILE",
        help="File with one target per line (host:port or host)",
    )

    check_group = p.add_argument_group("check selection")
    check_group.add_argument("--all", action="store_true", help="Run all available checks")
    check_group.add_argument(
        "--cve", metavar="CVE_ID", nargs="+",
        help="Run only the specified CVE check(s)",
    )

    run_group = p.add_argument_group("run options")
    run_group.add_argument(
        "--dump-creds", action="store_true",
        help="Enable credential extraction for CVE-2018-13379 (opt-in)",
    )
    run_group.add_argument("--threads", type=int, default=10, metavar="N",
                           help="Number of concurrent check threads (default: 10)")
    run_group.add_argument("--timeout", type=int, default=10, metavar="SECONDS",
                           help="Per-request timeout in seconds (default: 10)")
    run_group.add_argument(
        "--skip-verify", action="store_true",
        help="Skip pre-flight FortiGate verification (use for scripted/bulk scanning)",
    )

    out_group = p.add_argument_group("output")
    out_group.add_argument("--output", metavar="FILE", help="Save results to file")
    out_group.add_argument(
        "--format", choices=["table", "json", "csv"], default="table",
        help="Output format for --output (default: table)",
    )
    out_group.add_argument("--no-color", action="store_true",
                           help="Disable coloured terminal output")
    return p


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    global _COLOR

    parser = _build_parser()
    args = parser.parse_args()

    if getattr(args, "no_color", False):
        _COLOR = False

    print(_c(BANNER, Fore.CYAN if _COLOR else ""))

    if args.list:
        _list_checks()
        return

    if not args.target and not args.file:
        args = _interactive()

    # Build target list
    targets: List[Tuple[str, int]] = []
    if args.target:
        for raw in args.target:
            try:
                targets.append(_parse_target(raw))
            except ValueError as e:
                print(_c(f"  [!] Invalid target '{raw}': {e}", Fore.RED if _COLOR else ""))
                sys.exit(1)
    if args.file:
        if not os.path.isfile(args.file):
            print(_c(f"  [!] File not found: {args.file}", Fore.RED if _COLOR else ""))
            sys.exit(1)
        targets.extend(_load_targets_file(args.file))

    if not targets:
        print(_c("  [!] No valid targets.", Fore.RED if _COLOR else ""))
        sys.exit(1)

    # Resolve which checks to run
    if args.all:
        check_ids = list(REGISTRY.keys())
    elif args.cve:
        check_ids = []
        for cid in args.cve:
            cid_up = cid.upper()
            if cid_up not in REGISTRY:
                print(_c(f"  [!] Unknown CVE ID: {cid}  (use --list to see available checks)",
                         Fore.RED if _COLOR else ""))
                sys.exit(1)
            check_ids.append(cid_up)
    else:
        print(_c("  [!] Specify --all or --cve <ID> to select checks.", Fore.RED if _COLOR else ""))
        sys.exit(1)

    # Pre-flight verification
    if not _run_preflight(targets, skip=getattr(args, "skip_verify", False)):
        sys.exit(0)

    # Print run summary
    print(_c(f"  Targets : {len(targets)}", Fore.WHITE if _COLOR else ""))
    print(_c(f"  Checks  : {', '.join(check_ids)}", Fore.WHITE if _COLOR else ""))
    print(_c(f"  Threads : {args.threads}", Fore.WHITE if _COLOR else ""))
    if args.dump_creds and "CVE-2018-13379" in check_ids:
        print(_c("  Mode    : credential dump ENABLED for CVE-2018-13379", Fore.MAGENTA if _COLOR else ""))
    print()
    print("  " + "─" * 110)
    print(f"  {'Status':<15}  {'CVE ID':<22}  {'Target':<22}  Detail")
    print("  " + "─" * 110)

    results = _run_checks(targets, check_ids, args.dump_creds, args.threads)

    print("  " + "─" * 110)

    vuln    = sum(1 for r in results if r.status == "VULNERABLE")
    patched = sum(1 for r in results if r.status == "PATCHED")
    unknown = sum(1 for r in results if r.status in ("UNKNOWN", "NOT_FOUND"))
    errors  = sum(1 for r in results if r.status == "ERROR")

    print(f"\n  Summary: "
          + _c(f"{vuln} VULNERABLE", Fore.RED if _COLOR else "") + "  "
          + _c(f"{patched} PATCHED", Fore.GREEN if _COLOR else "") + "  "
          + _c(f"{unknown} UNKNOWN", Fore.YELLOW if _COLOR else "") + "  "
          + _c(f"{errors} ERROR", Fore.CYAN if _COLOR else ""))

    if args.output:
        fmt = getattr(args, "format", "table")
        if fmt == "json":
            _save_json(results, args.output)
        elif fmt == "csv":
            _save_csv(results, args.output)
        else:
            with open(args.output, "w") as fh:
                for r in results:
                    fh.write(f"{r.status:<12}  {r.cve:<22}  {r.target:<22}  {r.detail}\n")
        print(_c(f"\n  Results saved to {args.output}", Fore.GREEN if _COLOR else ""))


if __name__ == "__main__":
    main()
