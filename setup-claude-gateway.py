#!/usr/bin/env python3
r"""
Claude Desktop Custom Gateway Setup — Standalone Edition
===========================================================

Sets up Claude Desktop to use any Anthropic-compatible API gateway
WITHOUT requiring Ollama. This reverse-engineers and replicates what
`ollama launch claude-desktop` does, then patches the gateway URL/key.

For non-Anthropic gateways (Kimi, OpenRouter, etc.), the script uses the
`inferenceModels` config field to bypass model discovery and present the
gateway's model as an Anthropic-compatible one.

Prerequisites:
    - Python 3.7+
    - Claude Desktop installed

OS Support:
    - Windows (legacy %LOCALAPPDATA%\Claude-3p and MSIX sandbox)
    - macOS (~/Library/Application Support/Claude-3p)
    - Linux (~/.config/Claude-3p)

Usage (interactive):
    python setup-claude-gateway.py

Usage (non-interactive):
    python setup-claude-gateway.py \
        --base-url https://api.kimi.com/coding/ \
        --api-key sk-xxxxxxxx \
        --model-id claude-sonnet-4-5

Usage (restore stock Anthropic mode):
    python setup-claude-gateway.py --restore

Optional app-bundle patch:
    The desktop app validates custom model route names against a hard-coded
    banword regex (competitor model names: gpt, gemini, glm, grok, llama, ...).
    Names that do not look like Anthropic models are rejected and never shown.

    `--patch-model-names` rewrites the validator inside app.asar so any model
    name is accepted. It also:

      - recomputes per-file SHA256 integrity entries in the asar header
        (Electron verifies them on load),
      - updates the header hash recorded in Info.plist
        (ElectronAsarIntegrity) on macOS,
      - patches the settings-UI renderer copy of the validator (ion-dist,
        lives outside app.asar) — otherwise adding custom models in Settings
        still fails with "Doesn't look like an Anthropic model",
      - neutralizes the Cowork VM start gate and seeds the
        vm-support-probe.json caches with virtSupport=supported,
      - re-signs the bundle ad-hoc WITH entitlements (virtualization, JIT,
        ...) + hardened runtime — otherwise macOS refuses to launch the app
        and Virtualization.framework refuses to create the workspace VM.

    `--unpatch-app` restores the original app.asar from the backup.
    `--status` shows what is currently applied.

    python setup-claude-gateway.py --patch-model-names          # patch app only
    python setup-claude-gateway.py --unpatch-app                # revert app patch
    python setup-claude-gateway.py --status                     # diagnostics
    python setup-claude-gateway.py --asar-path /path/app.asar   # explicit bundle

Note:
    Claude Desktop auto-updates replace app.asar, wiping all app patches.
    Re-run this script after an update if foreign model names or the
    workspace stop working.
"""

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import struct
import subprocess
import sys
from pathlib import Path

# Force UTF-8 on Windows to avoid UnicodeEncodeError
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")


# ---------------------------------------------------------------------------
# Simple ANSI colors (works on Windows 10+, macOS, Linux)
# ---------------------------------------------------------------------------
class Colors:
    CYAN = "\033[36m"
    GREEN = "\033[32m"
    RED = "\033[31m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def info(msg: str):
    print(f"{Colors.CYAN}>{Colors.RESET} {msg}")


def success(msg: str):
    print(f"{Colors.GREEN}OK{Colors.RESET} {msg}")


def error(msg: str):
    print(f"{Colors.RED}ERR{Colors.RESET} {msg}")


def warn(msg: str):
    print(f"{Colors.YELLOW}WARN{Colors.RESET} {msg}")


def banner():
    print(f"{Colors.BLUE}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}  Claude Desktop Custom Gateway Setup{Colors.RESET}")
    print(f"  Standalone — no Ollama required")
    print(f"{Colors.BLUE}{'='*60}{Colors.RESET}")
    print()


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
CONFIG_ID = "00000000-0000-4000-8000-000000000114"

# Unique prefix of the banword regex literal compiled into the app bundles:
#   SS=/ark-code|astron|command-r|deepseek|doubao|gemini|gemma|glm|gpt|grok|...|dpsk/
BANLIST_ANCHOR = b"ark-code|astron|command-r|deepseek"

# ---------------------------------------------------------------------------
# OS detection & path resolution
# ---------------------------------------------------------------------------

def detect_os() -> str:
    system = platform.system()
    if system == "Windows":
        return "windows"
    elif system == "Darwin":
        return "macos"
    elif system == "Linux":
        return "linux"
    return "unknown"


def get_claude_3p_dir() -> Path:
    r"""
    Resolve the Claude-3p application data directory.

    Priority:
        Windows legacy -> %LOCALAPPDATA%\Claude-3p
        Windows MSIX   -> %LOCALAPPDATA%\Packages\Claude_*\LocalCache\Roaming\Claude-3p
        macOS          -> ~/Library/Application Support/Claude-3p
        Linux          -> ~/.config/Claude-3p
    """
    os_name = detect_os()
    home = Path.home()

    if os_name == "windows":
        local_appdata = Path(os.environ.get("LOCALAPPDATA", home / "AppData" / "Local"))

        # 1. Legacy direct path
        legacy = local_appdata / "Claude-3p"
        if legacy.exists():
            return legacy

        # 2. MSIX sandbox path (Store installs)
        packages_dir = local_appdata / "Packages"
        if packages_dir.exists():
            for pkg in packages_dir.glob("Claude_*"):
                candidate = pkg / "LocalCache" / "Roaming" / "Claude-3p"
                if candidate.exists():
                    return candidate

        # 3. Default to legacy path (create if needed)
        return legacy

    elif os_name == "macos":
        return home / "Library" / "Application Support" / "Claude-3p"

    elif os_name == "linux":
        return home / ".config" / "Claude-3p"

    else:
        raise RuntimeError(f"Unsupported operating system: {platform.system()}")


def get_backup_dir(override: str = None) -> Path:
    """Return the directory where we store backups of original configs."""
    if override:
        return Path(override).expanduser()
    os_name = detect_os()
    home = Path.home()
    if os_name == "windows":
        local_appdata = Path(os.environ.get("LOCALAPPDATA", home / "AppData" / "Local"))
        return local_appdata / "ClaudeGatewayPatchBackup"
    elif os_name == "macos":
        return home / "Library" / "Application Support" / "ClaudeGatewayPatchBackup"
    else:
        return home / ".config" / "ClaudeGatewayPatchBackup"


# ---------------------------------------------------------------------------
# App bundle (app.asar) discovery
# ---------------------------------------------------------------------------

def find_app_asar(explicit: str = None):
    """
    Locate the Claude Desktop Electron bundle (app.asar) across platforms.

    Returns a Path or None. Explicit --asar-path always wins.
    """
    if explicit:
        p = Path(explicit).expanduser()
        return p if p.exists() else None

    os_name = detect_os()
    home = Path.home()
    candidates = []

    if os_name == "macos":
        for app_dir in (Path("/Applications/Claude.app"),
                        home / "Applications" / "Claude.app"):
            candidates.append(app_dir / "Contents" / "Resources" / "app.asar")

    elif os_name == "windows":
        local_appdata = Path(os.environ.get("LOCALAPPDATA", home / "AppData" / "Local"))
        # NSIS per-user installs: %LOCALAPPDATA%\AnthropicClaude\app-<ver>\resources\
        anthropic_dir = local_appdata / "AnthropicClaude"
        if anthropic_dir.exists():
            versioned = []
            for d in anthropic_dir.glob("app-*"):
                m = re.match(r"app-(\d+(?:\.\d+)*)", d.name)
                if m:
                    versioned.append((tuple(int(x) for x in m.group(1).split(".")), d))
            for _, d in sorted(versioned, reverse=True):
                candidates.append(d / "resources" / "app.asar")
        candidates.append(local_appdata / "Programs" / "Claude" / "resources" / "app.asar")
        candidates.append(local_appdata / "Claude" / "resources" / "app.asar")

    elif os_name == "linux":
        candidates += [
            Path("/opt/Claude/resources/app.asar"),
            Path("/opt/claude-desktop/resources/app.asar"),
            Path("/usr/lib/claude-desktop/resources/app.asar"),
            Path("/usr/share/claude-desktop/resources/app.asar"),
            Path("/usr/local/lib/claude-desktop/resources/app.asar"),
            home / ".local" / "share" / "Claude" / "resources" / "app.asar",
        ]
        # Snap (read-only squashfs)
        snap = home / "snap" / "claude-desktop"
        if snap.exists():
            for d in sorted(snap.glob("current/**/resources/app.asar")):
                candidates.append(d)

    for c in candidates:
        if c.exists():
            if "WindowsApps" in c.parts:
                warn(f"Store/MSIX install found but not writable: {c}")
                warn("Patch the regular EXE installer build instead.")
                continue
            return c
    return None


# ---------------------------------------------------------------------------
# Model-name banword patch engine (byte-level, length preserving)
# ---------------------------------------------------------------------------

def _match_brace(data: bytes, open_idx: int) -> int:
    """Given index of '{' return index of matching '}' or -1."""
    depth = 0
    for i in range(open_idx, len(data)):
        b = data[i]
        if b == 0x7B:      # '{'
            depth += 1
        elif b == 0x7D:    # '}'
            depth -= 1
            if depth == 0:
                return i
    return -1


def _prev_ident(data: bytes, idx: int) -> bytes:
    """Walk backwards over [A-Za-z0-9_$] starting at idx-1; return identifier."""
    end = idx
    start = idx
    while start > 0 and (chr(data[start - 1]).isalnum() or data[start - 1] in (0x5F, 0x24)):
        start -= 1
    return data[start:end]


_FUNC_RE = re.compile(rb"function\s+([A-Za-z0-9_$]+)\s*\(([^()]*)\)\s*\{")


def patch_banword_validators(data: bytes):
    """
    Rewrite the model-name validators compiled into a JS bundle so that any
    name is accepted.

    Finds every banword regex literal (anchored on its unique word list),
    resolves the variable holding it and neutralizes the adjacent functions:

      validator  `function X(e){...BAN.test(t)?!1:...}` -> `{return!0}`
      ban-probe  `function X(e){return BAN.test(...)}`  -> `{return!1}`

    Replacements are padded with spaces to the original byte span length so
    file sizes stay identical (asar offsets remain valid).

    Returns (new_data, patched_count, already_patched_count).
    """
    edits = []  # (start, end, replacement)
    already = 0

    pos = 0
    while True:
        anchor = data.find(BANLIST_ANCHOR, pos)
        if anchor < 0:
            break
        pos = anchor + 1

        # Opening '/' of the regex literal.
        r_start = anchor - 1 if data[anchor - 1:anchor] == b"/" else data.rfind(b"/", 0, anchor)
        if r_start < 0:
            continue

        # Variable assigned to the regex: <ident>=/.../
        eq = r_start - 1
        if data[eq:eq + 1] != b"=":
            continue
        banvar = _prev_ident(data, eq)
        if not banvar:
            continue

        # Closing '/'; body is known to contain no slashes. Consume flags.
        r_end = data.find(b"/", anchor)
        if r_end < 0:
            continue
        f = r_end + 1
        while chr(data[f]).isalpha() and data[f:f + 1] != b"_":
            f += 1

        # Adjacent tiny functions referencing the banlist live right after.
        window = data[f:min(f + 900, len(data))]
        for m in _FUNC_RE.finditer(window):
            open_idx = f + m.end() - 1
            close_idx = _match_brace(data, open_idx)
            if close_idx < 0:
                continue
            span_start = f + m.start()
            body = data[open_idx + 1:close_idx]

            test_call = banvar + b".test"
            pure_probe = re.fullmatch(
                rb"\s*return\s+" + re.escape(banvar) + rb"\.test\(.+\)\s*;?\s*", body
            )
            validator = test_call in body and re.search(rb"\?\s*!1\s*:", body)

            if validator:
                new_body = b"return!0"
            elif pure_probe:
                new_body = b"return!1"
            elif body.strip() in (b"return!0", b"return!1"):
                already += 1
                continue
            else:
                continue

            prefix = data[span_start:open_idx + 1]   # 'function NAME(args){'
            replacement = prefix + new_body + b"}"
            pad = (close_idx + 1) - span_start - len(replacement)
            if pad < 0:
                continue  # should never happen: bodies only shrink
            replacement += b" " * pad
            edits.append((span_start, close_idx + 1, replacement))

    if not edits:
        return data, 0, already

    out = data
    for start, end, repl in sorted(edits, key=lambda e: e[0], reverse=True):
        assert len(repl) == end - start
        out = out[:start] + repl + out[end:]
    return out, len(edits), already


def patch_banword_validators_negated(data: bytes):
    """
    Same as patch_banword_validators but for the inverted validator shape used
    by the settings-UI renderer bundle:

      `function X(e){const t=e.toLowerCase();return!BAN.test(t)&&(A.test(t)||W.some(...))}`

    The negation makes the ternary-based classifier above miss it.
    Returns (new_data, patched_count, already_patched_count).
    """
    edits = []
    already = 0

    pos = 0
    while True:
        anchor = data.find(BANLIST_ANCHOR, pos)
        if anchor < 0:
            break
        pos = anchor + 1

        r_start = anchor - 1 if data[anchor - 1:anchor] == b"/" else data.rfind(b"/", 0, anchor)
        if r_start < 0:
            continue
        eq = r_start - 1
        if data[eq:eq + 1] != b"=":
            continue
        banvar = _prev_ident(data, eq)
        if not banvar:
            continue
        r_end = data.find(b"/", anchor)
        if r_end < 0:
            continue
        f = r_end + 1
        while chr(data[f]).isalpha() and data[f:f + 1] != b"_":
            f += 1

        window = data[f:min(f + 1200, len(data))]
        for m in _FUNC_RE.finditer(window):
            open_idx = f + m.end() - 1
            close_idx = _match_brace(data, open_idx)
            if close_idx < 0:
                continue
            span_start = f + m.start()
            body = data[open_idx + 1:close_idx]

            neg_validator = re.search(
                rb"!\s*" + re.escape(banvar) + rb"\.test", body
            )
            pure_probe = re.fullmatch(
                rb"\s*return\s+" + re.escape(banvar) + rb"\.test\(.+\)\s*;?\s*", body
            )

            if neg_validator:
                new_body = b"return!0"
            elif pure_probe:
                new_body = b"return!1"
            elif body.strip() in (b"return!0", b"return!1"):
                already += 1
                continue
            else:
                continue

            prefix = data[span_start:open_idx + 1]
            replacement = prefix + new_body + b"}"
            pad = (close_idx + 1) - span_start - len(replacement)
            if pad < 0:
                continue
            replacement += b" " * pad
            edits.append((span_start, close_idx + 1, replacement))

    if not edits:
        return data, 0, already

    out = data
    for start, end, repl in sorted(edits, key=lambda e: e[0], reverse=True):
        assert len(repl) == end - start
        out = out[:start] + repl + out[end:]
    return out, len(edits), already


def _asar_parse_header(data: bytes):
    """
    Parse the asar pickle header. Returns
    (header_dict, json_start, json_end, files_base) or None.
    """
    if len(data) < 16 or data[0:4] != b"\x04\x00\x00\x00":
        return None
    pickle_size = struct.unpack("<I", data[4:8])[0]
    json_size = struct.unpack("<I", data[12:16])[0]
    json_start = 16
    json_end = json_start + json_size
    try:
        hdr = json.loads(data[json_start:json_end].decode("utf-8"))
    except Exception:
        return None
    return hdr, json_start, json_end, 8 + pickle_size


def _asar_iter_files(node, path=""):
    """Yield (relative_path, entry_dict) for every real file in the tree."""
    for name, child in node.get("files", {}).items():
        p = f"{path}/{name}"
        if "files" in child:
            yield from _asar_iter_files(child, p)
        elif "offset" in child and "size" in child:
            yield p, child


def _asar_integrity(content: bytes, block_size: int):
    """Compute @electron/asar integrity fields for content."""
    h = hashlib.sha256(content).hexdigest()
    blocks = [hashlib.sha256(content[i:i + block_size]).hexdigest()
              for i in range(0, max(len(content), 1), block_size)]
    return h, blocks


_VM_GATE_ANCHOR = b"?.isVirtualizationSupported?.();if("


def patch_vm_start_gate(data: bytes):
    """
    Neutralize the startVM bail-out that refuses to boot the Cowork VM when
    the native probe reports anything but `supported` (our re-signed build
    fails Anthropic's internal signature/entitlement self-check).

        if(e!==void 0&&e!==`supported`){ ...skip... }   ->   if(false      &&...)

    Same-length replacement. Returns (new_data, count).
    """
    out = bytearray(data)
    count = 0
    pos = 0
    while True:
        i = out.find(_VM_GATE_ANCHOR, pos)
        if i < 0:
            break
        pos = i + 1
        # anchor ends with ';if(' -> variable name starts right here
        j = i + len(_VM_GATE_ANCHOR)
        k = j
        while k < len(out) and (chr(out[k]).isalnum() or out[k] in (0x5F, 0x24)):
            k += 1
        var = bytes(out[j:k])
        tail = b"!==void 0&&" + var + b"!==`supported`)"
        if not var or bytes(out[k:k + len(tail)]) != tail:
            continue
        span_start = j                    # '<var>!==void 0'
        span_end = k + len(b"!==void 0")  #
        repl = b"false" + b" " * (span_end - span_start - 5)
        assert len(repl) == span_end - span_start
        out[span_start:span_end] = repl
        count += 1
    return bytes(out), count


def _asar_read_file(data: bytes, base: int, entry: dict) -> bytes:
    off = base + int(entry["offset"])
    return bytes(data[off:off + int(entry["size"])])


def find_ion_dist_dir(asar_path: Path):
    """Locate the renderer web bundle (ion-dist) shipped next to app.asar."""
    if detect_os() == "macos":
        app = _find_app_bundle(asar_path)
        if not app:
            return None
        d = app / "Contents" / "Resources" / "ion-dist"
    else:
        d = asar_path.parent / "ion-dist"
    return d if d and d.exists() else None


def patch_ion_dist(ion_dir: Path, backup_dir: Path):
    """
    Patch the renderer (settings UI) copies of the banword validators that
    live outside app.asar. Originals are backed up for --unpatch-app.
    Returns number of files patched.
    """
    patched = []
    for f in sorted(ion_dir.rglob("*.js")):
        try:
            raw = f.read_bytes()
        except Exception:
            continue
        if BANLIST_ANCHOR not in raw:
            continue
        new, n1, _ = patch_banword_validators(raw)
        new, n2, al = patch_banword_validators_negated(new)
        if n1 == 0 and n2 == 0:
            continue
        rel = f.relative_to(ion_dir)
        bak = backup_dir / "ion-dist" / rel
        if not bak.exists():
            bak.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(f, bak)
        try:
            f.write_bytes(new)
        except PermissionError:
            warn(f"No write access to {f} — skipped.")
            continue
        patched.append(str(rel))
    return patched


def restore_ion_dist(ion_dir: Path, backup_dir: Path) -> int:
    """Restore renderer files previously backed up by patch_ion_dist."""
    src_root = backup_dir / "ion-dist"
    if not src_root.exists():
        return 0
    restored = 0
    for f in sorted(src_root.rglob("*")):
        if not f.is_file():
            continue
        rel = f.relative_to(src_root)
        target = ion_dir / rel
        if target.exists():
            shutil.copy2(f, target)
            restored += 1
    return restored


def seed_vm_probe_cache(app_version: str):
    """
    Pre-seed vm-support-probe.json caches so both normal and 3p profiles see
    virtSupport=supported without invoking the native probe (which fails on
    any non-Anthropic code signature).
    """
    rel = platform.release()
    arch = platform.machine()
    key = f"{app_version}|{rel}|{arch}"
    hw_key = f"{rel}|{arch}"
    payload = json.dumps({"key": key, "hardwareKey": hw_key, "virtSupport": "supported"})
    home = Path.home()
    candidates = []
    if detect_os() == "macos":
        base = home / "Library" / "Application Support"
        candidates = [base / "Claude", base / "Claude-3p"]
    elif detect_os() == "windows":
        appdata = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
        candidates = [appdata / "Claude", appdata / "Claude-3p"]
    elif detect_os() == "linux":
        cfg = home / ".config"
        candidates = [cfg / "Claude", cfg / "Claude-3p"]
    for d in candidates:
        d.mkdir(parents=True, exist_ok=True)
        try:
            target = d / "vm-support-probe.json"
            target.write_text(payload, encoding="utf-8")
            success(f"Seeded VM probe cache: {target}")
        except Exception as e:
            warn(f"Could not seed {d / 'vm-support-probe.json'}: {e}")


# ---------------------------------------------------------------------------
# Status / diagnostics
# ---------------------------------------------------------------------------

def _asar_app_version(hdr, data: bytes, base: int):
    for rel_path, entry in _asar_iter_files(hdr):
        if rel_path == "/package.json":
            try:
                return json.loads(_asar_read_file(data, base, entry)).get("version")
            except Exception:
                return None
    return None


def show_status(asar_path: Path, backup_dir: Path) -> int:
    """Print the current patch/integrity state of the app bundle."""
    print(f"{Colors.BOLD}App bundle{Colors.RESET}")
    if not asar_path or not asar_path.exists():
        error("app.asar not found")
        return 1
    print(f"  path:     {asar_path}")

    data = asar_path.read_bytes()
    parsed = _asar_parse_header(data)
    if not parsed:
        error("not a valid asar archive")
        return 1
    hdr, json_start, json_end, base = parsed
    version = _asar_app_version(hdr, data, base)
    print(f"  version:  {version or '?'}")

    # 1. Payload patches
    ban_total = ban_already = gate_left = 0
    for _, entry in _asar_iter_files(hdr):
        if "integrity" not in entry:
            continue
        chunk = _asar_read_file(data, base, entry)
        if BANLIST_ANCHOR in chunk:
            _, n, already = patch_banword_validators(chunk)
            ban_total += n
            ban_already += already
        if _VM_GATE_ANCHOR in chunk:
            _, ngate = patch_vm_start_gate(chunk)
            gate_left += ngate

    print(f"{Colors.BOLD}Model-name validators{Colors.RESET}")
    if BANLIST_ANCHOR not in data and ban_already == 0:
        state = "unknown (anchor absent — different app build?)"
    elif ban_total == 0:
        state = "patched ✓"
    else:
        state = f"NOT patched ({ban_total} validator(s) active)"
    print(f"  banword check: {state}")
    print(f"  VM start gate: {'patched ✓' if gate_left == 0 else f'NOT patched ({gate_left} active)'}")

    ion_dir = find_ion_dist_dir(asar_path)
    if ion_dir:
        ion_pending = 0
        ion_found = False
        for f in ion_dir.rglob("*.js"):
            try:
                raw = f.read_bytes()
            except Exception:
                continue
            if BANLIST_ANCHOR not in raw:
                continue
            ion_found = True
            _, n1, _ = patch_banword_validators(raw)
            _, n2, _ = patch_banword_validators_negated(raw)
            ion_pending += n1 + n2
        if ion_found:
            print(f"  settings UI:   {'patched ✓' if ion_pending == 0 else f'NOT patched ({ion_pending} active)'}")
    else:
        print("  settings UI:   ion-dist bundle not found")

    # 2. Header hash vs Info.plist (macOS)
    print(f"{Colors.BOLD}Integrity{Colors.RESET}")
    header_sha = hashlib.sha256(bytes(data[json_start:json_end])).hexdigest()
    if detect_os() == "macos":
        app_dir = _find_app_bundle(asar_path)
        plist_path = app_dir / "Contents" / "Info.plist" if app_dir else None
        plist_ok = "n/a"
        if plist_path and plist_path.exists():
            try:
                import plistlib
                with open(plist_path, "rb") as fh:
                    info_plist = plistlib.load(fh)
                entry = (info_plist.get("ElectronAsarIntegrity") or {}).get("Resources/app.asar")
                if isinstance(entry, dict):
                    plist_ok = "in sync ✓" if entry.get("hash") == header_sha else "MISMATCH ✗"
                else:
                    plist_ok = "no ElectronAsarIntegrity entry"
            except Exception as e:
                plist_ok = f"unreadable ({e})"
        print(f"  Info.plist header hash: {plist_ok}")
        print(f"  header sha256:          {header_sha[:16]}…")

        # Signature
        app_bundle = app_dir
        try:
            out = subprocess.run(
                ["codesign", "-dv", str(app_bundle)], capture_output=True, text=True
            ).stderr
            flags = re.search(r"flags=(\S+\s*\([^)]*\))", out)
            team = re.search(r"TeamIdentifier=(.*)", out)
            sig = flags.group(1).strip() if flags else "?"
            if "runtime" not in sig:
                sig += ", no-hardened-runtime"
            ent = subprocess.run(
                ["codesign", "-d", "--entitlements", "-", "--xml", str(app_bundle)],
                capture_output=True,
            ).stdout
            virt = b"virtualization" in ent
            print(f"  signature:              {sig}; "
                  f"virtualization entitlement: {'yes ✓' if virt else 'NO ✗'}")
        except Exception:
            pass
    else:
        print(f"  header sha256: {header_sha[:16]}…")

    # 3. VM probe caches
    print(f"{Colors.BOLD}VM probe cache{Colors.RESET}")
    rel, arch = platform.release(), platform.machine()
    expected_key = f"{version}|{rel}|{arch}" if version else None
    home = Path.home()
    dirs = []
    if detect_os() == "macos":
        b = home / "Library" / "Application Support"
        dirs = [b / "Claude", b / "Claude-3p"]
    elif detect_os() == "windows":
        a = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
        dirs = [a / "Claude", a / "Claude-3p"]
    elif detect_os() == "linux":
        c = home / ".config"
        dirs = [c / "Claude", c / "Claude-3p"]
    for d in dirs:
        f = d / "vm-support-probe.json"
        if not f.exists():
            print(f"  {d.name}: absent")
            continue
        try:
            j = json.loads(f.read_text(encoding="utf-8"))
            virt = j.get("virtSupport") or ("supported" if j.get("supported") else "?")
            fresh = (j.get("key") == expected_key) if expected_key else True
            print(f"  {d.name}: virtSupport={virt}, key={'fresh ✓' if fresh else 'STALE'}")
        except Exception as e:
            print(f"  {d.name}: unreadable ({e})")

    # 4. Backup
    bak = backup_dir / "app.asar.bak"
    print(f"{Colors.BOLD}Backup{Colors.RESET}")
    print(f"  {bak}: {'present (' + str(bak.stat().st_size) + ' bytes)' if bak.exists() else 'none'}")

    print()
    print(f"Run with {Colors.BOLD}--patch-model-names{Colors.RESET} to apply missing patches.")
    return 0


def patch_app_model_names(asar_path: Path, backup_dir: Path, resign: bool = True) -> bool:
    """
    Patch app.asar so foreign model names pass validation, keeping Electron's
    per-file ASAR integrity valid by recomputing hash/blocks inside the asar
    header (same-length hex substitutions -> offsets stay intact).
    """
    if claude_running():
        warn("Claude Desktop appears to be running — quit it fully before patching.")

    backup_dir.mkdir(parents=True, exist_ok=True)
    backup_path = backup_dir / "app.asar.bak"
    data = bytearray(asar_path.read_bytes())

    parsed = _asar_parse_header(bytes(data))
    if not parsed:
        error(f"Not a valid asar archive: {asar_path}")
        return False
    hdr, json_start, json_end, base = parsed

    total_patched = 0
    total_already = 0
    vm_gates_patched = 0
    files_patched = []
    header_subs = []  # (offset_key, old_hash, new_hash, old_blocks, new_blocks)

    app_version = None
    for rel_path, entry in _asar_iter_files(hdr):
        if rel_path == "/package.json" and app_version is None:
            try:
                app_version = json.loads(_asar_read_file(data, base, entry)).get("version")
            except Exception:
                pass

        if "integrity" not in entry:
            continue
        off = base + int(entry["offset"])
        size = int(entry["size"])
        chunk = bytes(data[off:off + size])
        if BANLIST_ANCHOR not in chunk and _VM_GATE_ANCHOR not in chunk:
            continue

        new_chunk, n, already = patch_banword_validators(chunk)
        total_already += already

        new_chunk, nvm = patch_vm_start_gate(new_chunk)
        vm_gates_patched += nvm

        if n == 0 and nvm == 0:
            continue
        assert len(new_chunk) == size
        data[off:off + size] = new_chunk
        files_patched.append(rel_path)

        integ = entry["integrity"]
        bs = int(integ.get("blockSize", 4194304))
        new_hash, new_blocks = _asar_integrity(new_chunk, bs)
        header_subs.append((entry["offset"], integ["hash"], new_hash,
                            list(integ["blocks"]), new_blocks))
        total_patched += n

    if not header_subs:
        if total_already:
            success(f"Already patched ({total_already} validator(s), {vm_gates_patched} VM gate(s)).")
            # Still bring the bundle to a fully working state: plist hash sync,
            # probe cache seed, renderer patch and an entitlement-bearing re-sign.
            header_sha_now = hashlib.sha256(bytes(data[json_start:json_end])).hexdigest()
            _update_macos_header_hash(asar_path, header_sha_now)
            if app_version:
                seed_vm_probe_cache(app_version)
            ion_dir = find_ion_dist_dir(asar_path)
            if ion_dir:
                ion_patched = patch_ion_dist(ion_dir, backup_dir)
                if ion_patched:
                    success(f"Patched settings-UI renderer validators in {len(ion_patched)} file(s):")
                    for p in ion_patched:
                        print(f"      ion-dist/{p}")
                else:
                    info("Settings-UI renderer already patched or contains no banword list.")
            else:
                warn("ion-dist renderer bundle not found — settings UI may still enforce banwords.")
            if resign:
                resign_macos_app(asar_path)
            return True
        warn("Banword list not found — app version may have changed. Nothing patched.")
        return False

    # Same-length hex substitutions inside the raw header JSON keep every
    # offset intact, so this remains a true in-place edit (no repack).
    text = bytes(data[json_start:json_end]).decode("utf-8")
    for off_key, old_h, new_h, old_blocks, new_blocks in header_subs:
        needle = f'"offset":"{off_key}","integrity":{{"algorithm":"SHA256","hash":"{old_h}"'
        idx = text.find(needle)
        if idx < 0:
            error("Header layout unexpected — aborting without write.")
            return False
        text = text[:idx] + needle.replace(old_h, new_h) + text[idx + len(needle):]
        old_j = json.dumps(old_blocks, separators=(",", ":")).replace('"', '\\"')
        new_j = json.dumps(new_blocks, separators=(",", ":")).replace('"', '\\"')
        blk_old = '"blocks":["' + '","'.join(old_blocks) + '"]'
        blk_new = '"blocks":["' + '","'.join(new_blocks) + '"]'
        i2 = text.find(blk_old, idx)
        if i2 < 0 or len(blk_old) != len(blk_new):
            error("Block list layout unexpected — aborting without write.")
            return False
        text = text[:i2] + blk_new + text[i2 + len(blk_old):]

    assert len(text.encode("utf-8")) == json_end - json_start
    new_header_bytes = text.encode("utf-8")
    new_header_sha256 = hashlib.sha256(new_header_bytes).hexdigest()
    data[json_start:json_end] = new_header_bytes

    if not backup_path.exists():
        shutil.copy2(asar_path, backup_path)
        info(f"Backup created: {backup_path}")
    else:
        info(f"Backup already exists, keeping pristine copy: {backup_path}")

    if len(data) != asar_path.stat().st_size:
        error("Internal error: archive length changed, aborting without write.")
        return False

    try:
        with open(asar_path, "r+b") as fh:
            fh.write(bytes(data))
    except PermissionError:
        error(f"No write access to {asar_path}. Close Claude / check permissions")
        if detect_os() == "windows":
            error("Try running the terminal as Administrator.")
        else:
            error("Try running with sudo (and keep ownership of the file).")
        return False

    success(f"Patched {total_patched} model-name validator(s) and {vm_gates_patched} VM start gate(s) "
            f"in {len(files_patched)} file(s):")
    for p in files_patched:
        print(f"      {p}")
    success("ASAR header integrity hashes updated.")

    ion_dir = find_ion_dist_dir(asar_path)
    if ion_dir:
        ion_patched = patch_ion_dist(ion_dir, backup_dir)
        if ion_patched:
            success(f"Patched settings-UI renderer validators in {len(ion_patched)} file(s):")
            for p in ion_patched:
                print(f"      ion-dist/{p}")
        else:
            info("Settings-UI renderer already patched or contains no banword list.")
    else:
        warn("ion-dist renderer bundle not found — settings UI may still enforce banwords.")

    if app_version:
        seed_vm_probe_cache(app_version)

    plist_status = _update_macos_header_hash(asar_path, new_header_sha256)
    if plist_status == "error":
        error("Info.plist is out of sync — the app will abort with 'Integrity check failed'.")
        return False
    if detect_os() != "macos" and detect_os() != "unknown":
        warn("Non-macOS note: some Windows builds embed integrity data in the exe; "
             "if Claude still refuses to start, reinstall or use --unpatch-app.")

    if resign:
        resign_macos_app(asar_path)

    print()
    print("Restart Claude Desktop to pick up the change:")
    print("  1. Quit via tray icon (fully quit)")
    print("  2. Relaunch from Applications / Start Menu")
    return True


def _find_app_bundle(asar_path: Path):
    """Walk up from an asar path to the enclosing .app bundle (macOS)."""
    p = asar_path
    while p.suffix != ".app" and p.parent != p:
        p = p.parent
    return p if p.suffix == ".app" else None


def _update_macos_header_hash(asar_path: Path, new_header_sha256: str) -> str:
    """
    Keep Info.plist ElectronAsarIntegrity in sync with the modified asar
    header. Returns a status string: 'updated', 'absent' or 'error'.
    """
    if detect_os() != "macos":
        return "absent"
    app_dir = _find_app_bundle(asar_path)
    if not app_dir:
        return "absent"
    import plistlib
    plist_path = app_dir / "Contents" / "Info.plist"
    if not plist_path.exists():
        return "absent"
    try:
        with open(plist_path, "rb") as fh:
            head = fh.read(64)
            fh.seek(0)
            data = plistlib.load(fh)
        fmt = plistlib.FMT_XML if head.lstrip().startswith(b"<?xml") else plistlib.FMT_BINARY
        integ = data.get("ElectronAsarIntegrity") or {}
        entry = integ.get("Resources/app.asar")
        if not isinstance(entry, dict) or "hash" not in entry:
            return "absent"
        entry["hash"] = new_header_sha256
        with open(plist_path, "wb") as fh:
            plistlib.dump(data, fh, fmt=fmt)
        success(f"Updated {plist_path} (ElectronAsarIntegrity hash)")
        return "updated"
    except Exception as e:
        warn(f"Could not update Info.plist integrity hash: {e}")
        return "error"


_ENTITLEMENTS_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
\t<key>com.apple.security.virtualization</key>
\t<true/>
\t<key>com.apple.security.cs.allow-jit</key>
\t<true/>
\t<key>com.apple.security.cs.allow-unsigned-executable-memory</key>
\t<true/>
\t<key>com.apple.security.cs.disable-library-validation</key>
\t<true/>
\t<key>com.apple.security.cs.allow-dyld-environment-variables</key>
\t<true/>
\t<key>com.apple.security.automation.apple-events</key>
\t<true/>
</dict>
</plist>
"""


def resign_macos_app(asar_path: Path) -> bool:
    """
    Ad-hoc re-sign the .app bundle after modifying resources (macOS only).

    Entitlements (virtualization, JIT, ...) are explicitly embedded and
    hardened runtime is enabled: Virtualization.framework refuses to create
    VMs without com.apple.security.virtualization even outside the App Store.
    """
    if detect_os() != "macos":
        return True
    app_dir = _find_app_bundle(asar_path)
    if not app_dir:
        return False

    import tempfile
    info(f"Re-signing (ad-hoc, with entitlements): {app_dir}")
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".plist", delete=False) as tf:
            tf.write(_ENTITLEMENTS_XML)
            ent_path = tf.name
        result = subprocess.run(
            ["codesign", "--force", "--deep", "--sign", "-",
             "--options", "runtime", "--entitlements", ent_path, str(app_dir)],
            capture_output=True, text=True,
        )
        os.unlink(ent_path)
    except FileNotFoundError:
        warn("codesign not found; skip re-signing.")
        return False
    except Exception as e:
        warn(f"Re-sign failed: {e}")
        return False
    if result.returncode != 0:
        warn(f"codesign failed: {result.stderr.strip()}")
        return False
    success("Re-signed OK (entitlements embedded)")
    return True


def claude_running() -> bool:
    """Best-effort detection of a running Claude Desktop process."""
    os_name = detect_os()
    try:
        if os_name == "windows":
            out = subprocess.run(
                ["tasklist", "/FI", "IMAGENAME eq Claude.exe", "/NH"],
                capture_output=True, text=True,
            ).stdout.lower()
            return "claude.exe" in out
        out = subprocess.run(["pgrep", "-f", "Claude"], capture_output=True, text=True).stdout
        return bool(out.strip())
    except Exception:
        return False


def unpatch_app_model_names(asar_path: Path, backup_dir: Path, resign: bool = True) -> bool:
    """Restore app.asar and renderer files from the pristine backups."""
    restored_any = False

    backup_path = backup_dir / "app.asar.bak"
    if backup_path.exists():
        try:
            shutil.copy2(backup_path, asar_path)
        except PermissionError:
            error(f"No write access to {asar_path}. Close Claude / elevate permissions.")
            return False
        success(f"Restored original bundle: {asar_path}")
        restored_any = True
    else:
        warn(f"No app.asar backup found at: {backup_path}.")
        info("The renderer patch can still be reverted if its backups exist.")

    ion_dir = find_ion_dist_dir(asar_path)
    if ion_dir:
        n = restore_ion_dist(ion_dir, backup_dir)
        if n:
            success(f"Restored {n} renderer file(s) from backup.")
            restored_any = True

    if not restored_any:
        return False
    if resign:
        resign_macos_app(asar_path)
    print("Restart Claude Desktop to apply.")
    return True


# ---------------------------------------------------------------------------
# Config I/O
# ---------------------------------------------------------------------------

def read_json(path: Path) -> dict:
    if path.exists():
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            warn(f"Could not parse {path}: {e}")
    return {}


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def backup_file(src: Path, backup_dir: Path) -> Path | None:
    if not src.exists():
        return None
    backup_dir.mkdir(parents=True, exist_ok=True)
    dst = backup_dir / src.name
    shutil.copy2(src, dst)
    return dst


def backup_directory(src: Path, backup_dir: Path) -> Path | None:
    if not src.exists():
        return None
    backup_dir.mkdir(parents=True, exist_ok=True)
    dst = backup_dir / src.name
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst)
    return dst


# ---------------------------------------------------------------------------
# Core patching logic
# ---------------------------------------------------------------------------

def patch_claude_desktop_config(claude_3p_dir: Path) -> None:
    """
    Ensure claude_desktop_config.json has deploymentMode: "3p" while
    preserving any existing user preferences.
    """
    config_path = claude_3p_dir / "claude_desktop_config.json"
    existing = read_json(config_path)
    existing["deploymentMode"] = "3p"
    write_json(config_path, existing)


def write_gateway_config(
    config_library: Path,
    base_url: str,
    api_key: str,
    model_id: str,
    auth_scheme: str = "bearer",
) -> None:
    """Write the gateway config and meta registry."""
    config_library.mkdir(parents=True, exist_ok=True)

    # Preserve any extra fields from existing config
    existing = read_json(config_library / f"{CONFIG_ID}.json")
    gateway_config = {
        **existing,
        "inferenceProvider": "gateway",
        "inferenceCredentialKind": "static",
        "inferenceGatewayApiKey": api_key,
        "inferenceGatewayAuthScheme": auth_scheme,
        "inferenceGatewayBaseUrl": base_url.rstrip("/") + "/" if base_url else base_url,
        "inferenceModels": [
            {
                "name": model_id,
                "labelOverride": model_id,
            }
        ],
    }
    write_json(config_library / f"{CONFIG_ID}.json", gateway_config)

    meta = {
        "appliedId": CONFIG_ID,
        "entries": [
            {"id": CONFIG_ID, "name": model_id}
        ],
    }
    write_json(config_library / "_meta.json", meta)


def apply_patch(claude_3p_dir: Path, base_url: str, api_key: str, model_id: str, auth_scheme: str) -> None:
    """Apply the full gateway patch to a single Claude-3p directory."""
    claude_3p_dir.mkdir(parents=True, exist_ok=True)
    patch_claude_desktop_config(claude_3p_dir)
    config_library = claude_3p_dir / "configLibrary"
    write_gateway_config(config_library, base_url, api_key, model_id, auth_scheme)


# ---------------------------------------------------------------------------
# Restore logic
# ---------------------------------------------------------------------------

def restore_stock_config(claude_3p_dir: Path) -> bool:
    """Restore stock Anthropic config by removing deploymentMode and configLibrary."""
    restored = False

    # 1. Remove deploymentMode from claude_desktop_config.json
    desktop_target = claude_3p_dir / "claude_desktop_config.json"
    if desktop_target.exists():
        data = read_json(desktop_target)
        if "deploymentMode" in data:
            data.pop("deploymentMode", None)
            write_json(desktop_target, data)
            restored = True

    # 2. Delete configLibrary entirely
    lib_target = claude_3p_dir / "configLibrary"
    if lib_target.exists():
        shutil.rmtree(lib_target)
        restored = True

    return restored


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def validate_url(url: str) -> bool:
    return url.startswith(("http://", "https://"))


def validate_api_key(key: str) -> bool:
    return len(key) >= 10


# ---------------------------------------------------------------------------
# Prompt helpers (for interactive mode)
# ---------------------------------------------------------------------------

def ask_input(prompt: str, default: str = "", password: bool = False) -> str:
    suffix = f" [{default}]" if default else ""
    if password:
        import getpass
        value = getpass.getpass(f"{prompt}{suffix}: ").strip()
        return value or default
    value = input(f"{prompt}{suffix}: ").strip()
    return value or default


def ask_confirm(prompt: str, default: bool = True) -> bool:
    default_str = "Y/n" if default else "y/N"
    value = input(f"{prompt} [{default_str}]: ").strip().lower()
    if not value:
        return default
    return value in ("y", "yes")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Route Claude Desktop to any Anthropic-compatible API gateway. No Ollama required.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                                    # Interactive mode
  %(prog)s --base-url https://api.kimi.com/coding/ --api-key sk-xxx --model-id claude-sonnet-4-5
  %(prog)s --restore                          # Revert to stock Anthropic mode
  %(prog)s --patch-model-names                # Allow foreign model names in the app
  %(prog)s --unpatch-app                      # Revert the app patch
  %(prog)s --status                           # Diagnostics
        """.strip(),
    )
    parser.add_argument("--base-url", help="Gateway base URL (e.g. https://api.example.com/coding/)")
    parser.add_argument("--api-key", help="API key for the gateway")
    parser.add_argument("--model-id", default="claude-sonnet-4-5", help="Anthropic model ID to present (default: claude-sonnet-4-5)")
    parser.add_argument("--auth-scheme", default="bearer", help="Auth scheme: bearer, basic, ... (default: bearer)")
    parser.add_argument("--restore", action="store_true", help="Restore original stock Anthropic config")
    parser.add_argument("--patch-model-names", action="store_true",
                        help="Patch app.asar so non-Anthropic model names (gpt, gemini, glm, ...) are accepted")
    parser.add_argument("--unpatch-app", action="store_true",
                        help="Restore app.asar from backup (revert --patch-model-names)")
    parser.add_argument("--status", action="store_true",
                        help="Show patch/integrity state of the app bundle and exit")
    parser.add_argument("--asar-path", help="Explicit path to Claude Desktop app.asar")
    parser.add_argument("--backup-dir", help="Override backup directory")
    parser.add_argument("--no-resign", action="store_true",
                        help="Skip ad-hoc codesign after patching (macOS)")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    banner()

    os_name = detect_os()
    info(f"Detected OS: {platform.system()}")

    try:
        claude_3p_dir = get_claude_3p_dir()
    except RuntimeError as e:
        error(str(e))
        return 1

    info(f"Claude-3p directory: {claude_3p_dir}")
    backup_dir = get_backup_dir(args.backup_dir)

    # ------------------------------------------------------------------
    # APP BUNDLE PATCH MODE (--unpatch-app / --patch-model-names / --status)
    # ------------------------------------------------------------------
    need_asar = args.patch_model_names or args.unpatch_app or args.status or args.asar_path
    asar_path = find_app_asar(args.asar_path) if need_asar else None

    if args.status:
        return show_status(asar_path, backup_dir)

    if args.unpatch_app:
        if not asar_path:
            error("app.asar not found. Pass --asar-path explicitly.")
            return 1
        unpatch_app_model_names(asar_path, backup_dir, resign=not args.no_resign)
        return 0

    standalone_patch = args.patch_model_names and not args.base_url and not args.api_key
    if standalone_patch:
        if not asar_path:
            error("Claude Desktop app.asar not found automatically.")
            error("Pass it explicitly: --asar-path '/path/to/Claude.app/Contents/Resources/app.asar'")
            return 1
        info(f"App bundle: {asar_path}")
        patch_app_model_names(asar_path, backup_dir, resign=not args.no_resign)
        return 0

    # ------------------------------------------------------------------
    # RESTORE MODE
    # ------------------------------------------------------------------
    if args.restore:
        info("Restoring stock Anthropic configuration...")

        paths_to_restore = [claude_3p_dir]
        if os_name == "windows":
            local_appdata = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
            packages_dir = local_appdata / "Packages"
            if packages_dir.exists():
                for pkg in packages_dir.glob("Claude_*"):
                    msix_claude_3p = pkg / "LocalCache" / "Roaming" / "Claude-3p"
                    if msix_claude_3p.exists():
                        paths_to_restore.append(msix_claude_3p)

        any_restored = False
        for p in paths_to_restore:
            if restore_stock_config(p):
                success(f"Restored: {p}")
                any_restored = True

        if any_restored:
            print()
            print(f"{Colors.GREEN}{'='*60}{Colors.RESET}")
            print(f"{Colors.BOLD}  RESTORE COMPLETE{Colors.RESET}")
            print(f"{Colors.GREEN}{'='*60}{Colors.RESET}")
            print("1. Fully quit Claude Desktop (tray icon → Quit)")
            print("2. Kill any remaining Claude.exe / Claude processes")
            print("3. Relaunch Claude Desktop from Start Menu / Applications")
            print()
            print("Claude Desktop will now connect to Anthropic's cloud.")
        else:
            info("Already in stock Anthropic mode. Nothing to restore.")

        if (backup_dir / "app.asar.bak").exists():
            print()
            info(f"An app bundle backup exists ({backup_dir / 'app.asar.bak'}).")
            info(f"Run with {Colors.BOLD}--unpatch-app{Colors.RESET} to also revert the model-name patch.")
        return 0

    # ------------------------------------------------------------------
    # PATCH MODE
    # ------------------------------------------------------------------
    base_url = args.base_url or ""
    api_key = args.api_key or ""

    if not base_url or not api_key:
        print(f"{Colors.BOLD}--- Gateway Configuration ---{Colors.RESET}")

    while not validate_url(base_url):
        base_url = ask_input("Base URL (e.g. https://api.example.com/coding/)")
        if not validate_url(base_url):
            error("URL must start with http:// or https://")

    while not validate_api_key(api_key):
        api_key = ask_input("API Key", password=True)
        if not validate_api_key(api_key):
            error("API Key looks too short. Please provide a valid key.")

    model_id = args.model_id
    if not args.base_url:
        model_input = ask_input("Anthropic Model ID", default="claude-sonnet-4-5")
        if model_input:
            model_id = model_input

    auth_scheme = args.auth_scheme
    if not args.base_url:
        scheme_input = ask_input("Auth Scheme", default="bearer")
        if scheme_input:
            auth_scheme = scheme_input

    patch_names = args.patch_model_names
    if not args.base_url and not patch_names:
        print()
        print(f"{Colors.BOLD}--- Optional: app bundle patch ---{Colors.RESET}")
        print("The app rejects model names containing banwords (gpt, gemini, glm, ...).")
        patch_names = ask_confirm("Patch app bundle to allow any model name?", default=False)

    # Confirm
    print()
    print("Review:")
    print(f"  Base URL: {base_url}")
    print(f"  API Key:  {'*' * min(len(api_key), 8)}...")
    print(f"  Model ID: {model_id}")
    print(f"  Auth:     {auth_scheme}")
    print()

    if not args.base_url:
        if not ask_confirm("Write configuration?", default=True):
            info("Aborted by user.")
            return 0

    # Backup existing state
    claude_3p_dir.mkdir(parents=True, exist_ok=True)
    backup_dir.mkdir(parents=True, exist_ok=True)

    desktop_backup = backup_file(claude_3p_dir / "claude_desktop_config.json", backup_dir)
    if desktop_backup:
        info(f"Backup created: {desktop_backup}")

    lib_backup = backup_directory(claude_3p_dir / "configLibrary", backup_dir)
    if lib_backup:
        info(f"Backup created: {lib_backup}")

    # Apply patch
    apply_patch(claude_3p_dir, base_url, api_key, model_id, auth_scheme)
    success(f"Configuration written to {claude_3p_dir}")

    # Also patch MSIX path on Windows if it exists
    if os_name == "windows":
        local_appdata = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        packages_dir = local_appdata / "Packages"
        if packages_dir.exists():
            for pkg in packages_dir.glob("Claude_*"):
                msix_claude_3p = pkg / "LocalCache" / "Roaming" / "Claude-3p"
                if msix_claude_3p.exists():
                    info(f"Also patching MSIX path: {msix_claude_3p}")
                    apply_patch(msix_claude_3p, base_url, api_key, model_id, auth_scheme)
                    success(f"MSIX path patched: {msix_claude_3p}")

    # Optional app bundle patch
    if patch_names:
        print()
        target_asar = asar_path or find_app_asar(args.asar_path)
        if not target_asar:
            warn("app.asar not found — skipping the model-name patch.")
            warn("Pass it explicitly: --asar-path '/path/to/Claude.app/Contents/Resources/app.asar'")
        else:
            info(f"Patching app bundle: {target_asar}")
            patch_app_model_names(target_asar, backup_dir, resign=not args.no_resign)

    # Final instructions
    print()
    print(f"{Colors.GREEN}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}  SETUP COMPLETE{Colors.RESET}")
    print(f"{Colors.GREEN}{'='*60}{Colors.RESET}")
    print("1. Fully quit Claude Desktop (tray icon → Quit)")
    print("2. Kill any remaining Claude.exe / Claude processes")
    print("3. Relaunch Claude Desktop from Start Menu / Applications")
    print()
    print("Your custom gateway should appear in the model picker.")
    print()
    print(f"Run with {Colors.BOLD}--restore{Colors.RESET} to revert to Anthropic's cloud.")

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nAborted.")
        sys.exit(130)
