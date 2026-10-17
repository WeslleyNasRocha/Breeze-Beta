#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "mcp[cli]>=1.2.0",
#     "capstone>=5.0.0",
#     "keystone-engine>=0.9.2",
# ]
# ///
"""Breeze MCP Server for Agentic Nintendo Switch Cheat Engineering.

Wraps Breeze's PC Connect protocol (TCP 6801) with high-level tools built for
universal reverse engineering and cheat development across all engines
(Unity IL2CPP, Unreal Engine, Native ARM64 C++, and GameMaker):
- Automatic 4096-byte chunked memory reads
- Typed memory reads/writes, freezes, and multi-field struct/object inspection
- Cross-engine function map caching & searching (Unity, Unreal, GameMaker, unwind)
- Cross-reference callers discovery via native 'xref call'
- Capstone ARM64 disassembler with automatic BL symbol & ADRP BSS pointer resolution
- Keystone ARM64 assembler & Atmosphere CheatVM (04000000 / Type 5/7/6) generator
- Dual SD card deployment (live dmnt + Breeze & Atmosphere SD card persistence)
"""

import bisect
import json
import math
import os
import re
import struct
import sys
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pcconnect import Breeze  # noqa: E402

try:
    try:
        from mcp.server.mcpserver import MCPServer as FastMCP  # noqa: E402
    except ImportError:
        from mcp.server.fastmcp import FastMCP  # noqa: E402
    mcp = FastMCP("breeze")
except ImportError:
    class DummyMCP:
        def tool(self):
            return lambda fn: fn
        def run(self):
            print("Error: MCP package not installed. Run with 'uv run breeze_mcp.py' or 'python3 breeze_mcp.py install'.")
            sys.exit(1)
    mcp = DummyMCP()

CACHE_DIR = os.path.join(os.path.expanduser("~"), ".breeze_pc")
MAX_PEEK_CHUNK = 4096


def _load_breeze_cfg() -> dict:
    cfg_path = os.path.join(os.path.expanduser("~"), ".breeze_pc.json")
    if os.path.exists(cfg_path):
        try:
            with open(cfg_path, "r", encoding="utf-8") as fp:
                return json.load(fp)
        except Exception:
            pass
    return {}


_breeze_cfg = _load_breeze_cfg()
_DEFAULT_HOST = os.environ.get("BREEZE_HOST") or _breeze_cfg.get("host") or "192.168.1.65"
_DEFAULT_CODE = os.environ.get("BREEZE_CODE") or _breeze_cfg.get("code") or "0303"
_DEFAULT_PORT = int(os.environ.get("BREEZE_PORT") or _breeze_cfg.get("port", 6801))

_STATE = {
    "host": _DEFAULT_HOST,
    "code": _DEFAULT_CODE,
    "port": _DEFAULT_PORT,
    "client": None,
    "fn_map_cache": {},  # (tid, bid) -> (sorted_offsets, [(offset, name), ...], name_to_offset)
}

RVALUE_KINDS = {
    0: "REAL(double)",
    1: "STRING",
    2: "ARRAY",
    3: "PTR",
    4: "VEC3",
    5: "UNDEFINED",
    6: "OBJECT",
    7: "INT32",
    8: "VEC4",
    9: "VEC44",
    10: "INT64",
    11: "ACCESSOR",
    12: "NULL",
    13: "BOOL",
    14: "ITERATOR",
    15: "REF",
}


def _get_client() -> Breeze:
    client = _STATE["client"]
    if client is not None:
        try:
            reply = client.cmd("ping")
            if reply.startswith("+OK"):
                return client
        except Exception:
            try:
                client.close()
            except Exception:
                pass
            _STATE["client"] = None

    try:
        client = Breeze(_STATE["host"], _STATE["code"], port=_STATE["port"], timeout=10)
    except OSError as e:
        raise ConnectionError(
            f"Cannot connect to Breeze at {_STATE['host']}:{_STATE['port']} ({e}). "
            "Ensure the Switch is awake and Breeze is running with PC Connect enabled."
        ) from e
    _STATE["client"] = client
    return client


def _parse_addr(b: Breeze, addr_expr: str | int, meta: Optional[dict] = None) -> int:
    if isinstance(addr_expr, int):
        return addr_expr
    s = str(addr_expr).strip()
    if meta is None and any(k in s.lower() for k in ("main", "heap", "alias", "m+")):
        meta = b.json("meta")
    s_low = s.lower()
    for prefix, key in (("main+", "main"), ("m+", "main"), ("heap+", "heap"), ("alias+", "alias")):
        if s_low.startswith(prefix):
            base = int(meta[key], 16)
            off_str = s[len(prefix):].strip()
            return base + int(off_str, 16)
    return int(s, 16) if s_low.startswith("0x") or any(c in s_low for c in "abcdef") else int(s, 0)


def _read_chunked(b: Breeze, addr: int, total_len: int) -> bytes:
    out = bytearray()
    rem = total_len
    cur = addr
    while rem > 0:
        n = min(rem, MAX_PEEK_CHUNK)
        chunk = b.peek(cur, n)
        out.extend(chunk)
        if len(chunk) < n:
            break
        cur += n
        rem -= n
    return bytes(out)


def _parse_map_file(local_path: str) -> tuple[list[int], list[tuple[int, str]], dict[str, int]]:
    entries: list[tuple[int, str]] = []
    name_to_off: dict[str, int] = {}
    with open(local_path, "r", encoding="utf-8", errors="replace") as fp:
        for line in fp:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"^(.+?)\s*=\s*(?:main\+)?0x([0-9a-fA-F]+)", line)
            if m:
                name, off_hex = m.group(1).strip(), m.group(2)
                off = int(off_hex, 16)
                entries.append((off, name))
                name_to_off[name] = off

    entries.sort(key=lambda x: x[0])
    offsets = [e[0] for e in entries]
    return offsets, entries, name_to_off


def _load_function_map(b: Optional[Breeze] = None) -> tuple[list[int], list[tuple[int, str]], dict[str, int]]:
    map_names = ("gm_function_map.txt", "il2cpp_function_map.txt", "ue_function_map.txt")
    if b is not None:
        meta = b.json("meta")
        tid = meta["title_id"].upper()
        bid = meta["build_id"].upper()
        key = (tid, bid)
        if key in _STATE["fn_map_cache"]:
            return _STATE["fn_map_cache"][key]

        files_info = b.files()
        chosen_map = None
        for f in files_info.get("files", []):
            if f["name"] in map_names:
                chosen_map = f["name"]
                break

        if not chosen_map:
            return [], [], {}

        local_dir = os.path.join(CACHE_DIR, f"{tid}_{bid}")
        os.makedirs(local_dir, exist_ok=True)
        local_path = os.path.join(local_dir, chosen_map)

        if not os.path.exists(local_path):
            b.get_file(chosen_map, local_path=local_path)

        parsed = _parse_map_file(local_path)
        _STATE["fn_map_cache"][key] = parsed
        return parsed

    # Offline fallback: use most recently modified map in ~/.breeze_pc
    if os.path.isdir(CACHE_DIR):
        candidates = []
        for sub in os.listdir(CACHE_DIR):
            sub_dir = os.path.join(CACHE_DIR, sub)
            if os.path.isdir(sub_dir):
                for mn in map_names:
                    p = os.path.join(sub_dir, mn)
                    if os.path.isfile(p):
                        candidates.append((os.path.getmtime(p), sub, p))
        if candidates:
            candidates.sort(reverse=True)
            _, sub, local_path = candidates[0]
            if sub in _STATE["fn_map_cache"]:
                return _STATE["fn_map_cache"][sub]
            parsed = _parse_map_file(local_path)
            _STATE["fn_map_cache"][sub] = parsed
            return parsed

    return [], [], {}


def _resolve_symbol(offsets: list[int], entries: list[tuple[int, str]], main_offset: int) -> Optional[str]:
    if not offsets:
        return None
    idx = bisect.bisect_right(offsets, main_offset) - 1
    if idx < 0:
        return None
    fn_off, fn_name = entries[idx]
    delta = main_offset - fn_off
    if delta == 0:
        return fn_name
    if 0 < delta < 0x20000:
        return f"{fn_name}+0x{delta:X}"
    return None


import functools
import time

def _safe_tool(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Exception as e:
            return json.dumps({
                "error": str(e),
                "tool": fn.__name__,
                "hint": "Ensure Switch screen is ON and Breeze is running with PC Connect enabled (Settings > PC connect)."
            }, indent=2)
    return wrapper


@mcp.tool()
def breeze_ping(host: str = "", port: int = 6801) -> str:
    """Quickly check if the Nintendo Switch is awake and Breeze PC Connect port is open."""
    import socket
    target_host = host if host else _STATE["host"]
    target_port = port if port else _STATE["port"]
    start = time.time()
    s = socket.socket()
    s.settimeout(3)
    try:
        s.connect((target_host, target_port))
        latency_ms = round((time.time() - start) * 1000, 1)
        s.close()
        return json.dumps({
            "status": "online",
            "host": target_host,
            "port": target_port,
            "latency_ms": latency_ms,
        }, indent=2)
    except Exception as e:
        return json.dumps({
            "status": "offline",
            "host": target_host,
            "port": target_port,
            "error": str(e),
        }, indent=2)


@mcp.tool()
@_safe_tool
def breeze_connect(host: str = "", code: str = "", port: int = 0) -> str:
    """Connect or switch to a Nintendo Switch running Breeze PC Connect.

    If host/code/port are omitted, defaults to BREEZE_HOST/BREEZE_CODE environment variables,
    ~/.breeze_pc.json, or 192.168.1.65:6801 (code 0303).
    """
    if _STATE["client"] is not None:
        try:
            _STATE["client"].close()
        except Exception:
            pass
        _STATE["client"] = None
    if host:
        _STATE["host"] = host.strip()
    if code:
        _STATE["code"] = str(code).strip()
    if port > 0:
        _STATE["port"] = int(port)
    b = _get_client()
    meta = b.json("meta")
    return json.dumps({"status": "connected", "banner": b.banner, "meta": meta}, indent=2)


@mcp.tool()
@_safe_tool
def breeze_list_cheats() -> str:
    """List all cheats currently registered in Breeze and dmnt, with their active state and ID."""
    b = _get_client()
    raw = b.cmd("cheats")
    lines = raw.splitlines()
    header = lines[0] if lines else ""
    cheats = []
    for l in lines[1:]:
        l = l.strip()
        if not l or l == ".":
            continue
        parts = l.split(" ", 2)
        if len(parts) >= 3:
            cheats.append({"id": int(parts[0]), "enabled": parts[1] == "on", "name": parts[2]})
        elif len(parts) == 2:
            cheats.append({"id": int(parts[0]), "enabled": parts[1] == "on", "name": ""})
    return json.dumps({"header": header, "cheats": cheats}, indent=2)


@mcp.tool()
@_safe_tool
def breeze_get_file_content(path: str) -> str:
    """Read and return the text content of any file from the Switch SD card (e.g. 'sdmc:/switch/breeze/cheats/...')."""
    b = _get_client()
    data = b.get_file(path)
    return data.decode("utf-8", "replace")


@mcp.tool()
@_safe_tool
def breeze_put_file_content(path: str, content: str) -> str:
    """Write text content to any file on the Switch SD card (e.g. 'sdmc:/switch/breeze/...')."""
    b = _get_client()
    b.fs_put(path, 0, content.encode("utf-8"))
    return f"Successfully wrote {len(content)} characters to {path}."


@mcp.tool()
@_safe_tool
def breeze_game_info() -> str:
    """Get attached game metadata (Title ID, Build ID, main/heap/alias bases), files, active cheats, and ai_notes.md."""
    b = _get_client()
    meta = b.json("meta")
    files = b.files()
    cheats_raw = b.cmd("cheats")
    notes = b.notes()
    return json.dumps({
        "meta": meta,
        "engine": files.get("engine"),
        "dir": files.get("dir"),
        "files": [f["name"] for f in files.get("files", [])],
        "cheats_summary": cheats_raw,
        "ai_notes": notes,
    }, indent=2)


@mcp.tool()
@_safe_tool
def breeze_update_notes(text: str) -> str:
    """Save reverse-engineering findings to ai_notes.md in the game's folder on the Switch."""
    b = _get_client()
    b.write_notes(text)
    return f"Successfully wrote {len(text)} chars to ai_notes.md on Switch."


@mcp.tool()
@_safe_tool
def breeze_read_typed(address: str, dtype: str = "double", count: int = 1) -> str:
    """Read typed values from Switch memory with automatic >4096-byte chunking.

    address: Hex address ('0x38C5F37220') or relative ('main+0x1D3C80', 'heap+0x7F137220').
    dtype: 'double' (8B IEEE-754), 'float' (4B), 'u32', 'i32', 'u64', 'i64', 'rvalue' (16B GameMaker RValue), or 'hex'.
    count: Number of elements (or byte length when dtype='hex').
    """
    b = _get_client()
    meta = b.json("meta")
    addr = _parse_addr(b, address, meta)
    dt = dtype.lower().strip()

    if dt == "hex":
        raw = _read_chunked(b, addr, count)
        return json.dumps({"address": f"0x{addr:X}", "bytes": len(raw), "hex": raw.hex()}, indent=2)

    if dt == "rvalue":
        raw = _read_chunked(b, addr, count * 16)
        items = []
        for i in range(count):
            chunk = raw[i * 16:(i + 1) * 16]
            if len(chunk) < 16:
                break
            d_val = struct.unpack("<d", chunk[:8])[0]
            u64_val = struct.unpack("<Q", chunk[:8])[0]
            flags, kind = struct.unpack("<II", chunk[8:16])
            items.append({
                "slot_address": f"0x{addr + i * 16:X}",
                "kind": RVALUE_KINDS.get(kind & 0xFFFFFF, f"UNKNOWN({kind})"),
                "double": d_val if math.isfinite(d_val) else str(d_val),
                "u64_hex": f"0x{u64_val:X}",
                "flags": f"0x{flags:X}",
            })
        return json.dumps({"base": f"0x{addr:X}", "rvalues": items}, indent=2)

    fmt_map = {
        "double": ("<d", 8),
        "float": ("<f", 4),
        "u32": ("<I", 4),
        "i32": ("<i", 4),
        "u64": ("<Q", 8),
        "i64": ("<q", 8),
    }
    if dt not in fmt_map:
        raise ValueError(f"Unsupported dtype '{dtype}'. Use double, float, u32, i32, u64, i64, rvalue, or hex.")

    fmt, sz = fmt_map[dt]
    raw = _read_chunked(b, addr, count * sz)
    vals = []
    for i in range(count):
        piece = raw[i * sz:(i + 1) * sz]
        if len(piece) < sz:
            break
        v = struct.unpack(fmt, piece)[0]
        entry = {"address": f"0x{addr + i * sz:X}", "value": v if not isinstance(v, float) or math.isfinite(v) else str(v)}
        if dt in ("u64", "u32"):
            entry["hex"] = f"0x{v:X}"
        vals.append(entry)
    return json.dumps({"dtype": dt, "results": vals}, indent=2)


@mcp.tool()
@_safe_tool
def breeze_write_typed(address: str, values: list[float | int], dtype: str = "double", hold: bool = False) -> str:
    """Write typed values (e.g. GameMaker 64-bit doubles) to memory and optionally freeze (hold) them."""
    b = _get_client()
    meta = b.json("meta")
    addr = _parse_addr(b, address, meta)
    dt = dtype.lower().strip()
    fmt_map = {
        "double": ("<d", 8),
        "float": ("<f", 4),
        "u32": ("<I", 4),
        "i32": ("<i", 4),
        "u64": ("<Q", 8),
        "i64": ("<q", 8),
    }
    if dt not in fmt_map:
        raise ValueError(f"Unsupported dtype '{dtype}'.")
    fmt, sz = fmt_map[dt]
    buf = bytearray()
    for v in values:
        buf.extend(struct.pack(fmt, float(v) if dt in ("double", "float") else int(v)))

    reply = b.cmd(f"poke {addr:X} {buf.hex()}")
    hold_replies = []
    if hold and sz in (1, 2, 4, 8):
        for i in range(len(values)):
            hold_replies.append(b.cmd(f"hold {addr + i * sz:X} {sz}"))

    return json.dumps({
        "address": f"0x{addr:X}",
        "bytes_written": len(buf),
        "poke_reply": reply,
        "hold_replies": hold_replies,
    }, indent=2)


@mcp.tool()
@_safe_tool
def breeze_inspect_object(address: str, start_offset: int = -0x40, end_offset: int = 0x100) -> str:
    """Inspect fields of a struct, class instance, or pointer table in memory around `address`.

    Scans 8-byte aligned slots from `address + start_offset` to `address + end_offset`.
    Identifies pointers into heap or main, and dereferences them to reveal live
    typed fields (double, float, u32, u64, pointers, ASCII strings, or tagged unions).
    Works across Unity IL2CPP, Unreal Engine, C++, and GameMaker object instances.
    """
    b = _get_client()
    meta = b.json("meta")
    base_addr = _parse_addr(b, address, meta)
    heap_base = int(meta["heap"], 16)
    heap_end = heap_base + int(meta["heap_size"], 16)
    main_base = int(meta["main"], 16)
    main_end = main_base + int(meta["main_size"], 16)

    scan_start = base_addr + start_offset
    scan_len = end_offset - start_offset
    raw = _read_chunked(b, scan_start, scan_len)

    rows = []
    for rel in range(0, len(raw) - 7, 8):
        slot_off = start_offset + rel
        slot_addr = base_addr + slot_off
        val_u64 = struct.unpack("<Q", raw[rel:rel + 8])[0]
        val_dbl = struct.unpack("<d", raw[rel:rel + 8])[0]

        off_label = f"+0x{slot_off:02X}" if slot_off >= 0 else f"-0x{-slot_off:02X}"
        info = {
            "offset": off_label,
            "slot_addr": f"0x{slot_addr:X}",
            "raw_u64": f"0x{val_u64:X}",
        }

        if heap_base <= val_u64 < heap_end or main_base <= val_u64 < main_end:
            region = f"heap+0x{val_u64 - heap_base:X}" if val_u64 >= heap_base and val_u64 < heap_end else f"main+0x{val_u64 - main_base:X}"
            info["points_to"] = f"0x{val_u64:X} ({region})"
            try:
                target_bytes = b.peek(val_u64, 16)
                t_dbl = struct.unpack("<d", target_bytes[:8])[0]
                t_u64 = struct.unpack("<Q", target_bytes[:8])[0]
                t_u32 = struct.unpack("<I", target_bytes[:4])[0]
                t_flt = struct.unpack("<f", target_bytes[:4])[0]
                t_flags, t_kind = struct.unpack("<II", target_bytes[8:16])

                deref_dict = {
                    "u64_hex": f"0x{t_u64:X}",
                    "u32": t_u32,
                    "float": round(t_flt, 4) if math.isfinite(t_flt) and abs(t_flt) < 1e10 else str(t_flt),
                    "double": round(t_dbl, 6) if math.isfinite(t_dbl) and abs(t_dbl) < 1e15 else str(t_dbl),
                }

                # Target points into main (common for vtable or Unity Il2CppClass pointers)
                if main_base <= t_u64 < main_end:
                    deref_dict["target_vtable_or_class"] = f"main+0x{t_u64 - main_base:X}"

                # Tagged union / RValue heuristic
                kind_idx = t_kind & 0xFFFFFF
                if kind_idx in RVALUE_KINDS:
                    deref_dict["tagged_kind"] = RVALUE_KINDS[kind_idx]

                info["deref"] = deref_dict
            except Exception as e:
                info["deref_error"] = str(e)
        else:
            if math.isfinite(val_dbl) and (val_dbl == 0.0 or 1e-6 <= abs(val_dbl) <= 1e12):
                info["inline_double"] = val_dbl
        rows.append(info)

    return json.dumps({"object_base": f"0x{base_addr:X}", "fields": rows}, indent=2)


@mcp.tool()
@_safe_tool
def breeze_inspect_container(address: str, start_offset: int = -0x40, end_offset: int = 0x100) -> str:
    """Inspect memory fields of a struct, class instance, or container (alias for breeze_inspect_object)."""
    return breeze_inspect_object(address, start_offset, end_offset)


@mcp.tool()
@_safe_tool
def breeze_find_refs(
    address: str,
    range_hex: int = 0x100,
    max_hits: int = 64,
    seconds: int = 30,
    filter_region: str = "",
) -> str:
    """Find all 8-byte aligned pointers in writable memory pointing to [address - range_hex, address].

    filter_region: Optional filter ('main', 'heap', 'alias') to isolate static anchors in main!
    """
    b = _get_client()
    meta = b.json("meta")
    addr = _parse_addr(b, address, meta)
    hdr, hits = b.refs(addr, rng=range_hex, max_hits=max_hits, seconds=seconds)
    if filter_region:
        fl = filter_region.lower()
        hits = [h for h in hits if fl in h.lower()]
    return json.dumps({"header": hdr, "hit_count": len(hits), "hits": hits}, indent=2)


@mcp.tool()
@_safe_tool
def breeze_walk_chain(base: str, offsets: list[str]) -> str:
    """Walk a CheatVM pointer chain (e.g. base='main+0x2083A60', offsets=['0x0', '+0x50']) and decode the target."""
    b = _get_client()
    lines = b.chain(base, *offsets)
    return "\n".join(lines)


@mcp.tool()
@_safe_tool
def breeze_search_functions(query: str, max_results: int = 50) -> str:
    """Search the game's function map (GameMaker gm_function_map.txt, Unity il2cpp, or Unreal) by substring or regex."""
    try:
        b = _get_client()
        _, entries, _ = _load_function_map(b)
    except Exception:
        # Fallback to offline cached maps if Switch is asleep or disconnected
        _, entries, _ = _load_function_map(None)

    if not entries:
        return json.dumps({"error": "No function map found. Run prep gm_functions / il2cpp_functions while connected."})

    try:
        pattern = re.compile(query, re.IGNORECASE)
    except re.error:
        pattern = re.compile(re.escape(query), re.IGNORECASE)

    matches = []
    for off, name in entries:
        if pattern.search(name):
            matches.append({"name": name, "main_offset": f"0x{off:X}", "expr": f"main+0x{off:X}"})
            if len(matches) >= max_results:
                break
    return json.dumps({"total_in_map": len(entries), "matches": matches}, indent=2)


@mcp.tool()
@_safe_tool
def breeze_find_callers(target: str, max_results: int = 50) -> str:
    """Find all functions and instructions in main that call the specified function or offset.

    target: Function name (e.g. 'gml_Script_scr_road_calc_gas_cost') or offset (e.g. '0x6D4F90' or 'main+0x6D4F90').
    Uses Breeze's native 'xref call' engine command and maps calling instructions to their containing functions.
    """
    b = _get_client()
    meta = b.json("meta")
    main_base = int(meta["main"], 16)
    offsets, entries, name_to_off = _load_function_map(b)

    target_str = target.strip()
    if target_str in name_to_off:
        target_off = name_to_off[target_str]
        target_name = target_str
    else:
        addr = _parse_addr(b, target_str, meta)
        target_off = addr - main_base if addr >= main_base else addr
        target_name = _resolve_symbol(offsets, entries, target_off) or f"main+0x{target_off:X}"

    caller_rvas = b.xref_call(main_base + target_off)

    callers = []
    for rva in caller_rvas:
        caller_sym = _resolve_symbol(offsets, entries, rva)
        callers.append({
            "caller_offset": f"0x{rva:X}",
            "expr": f"main+0x{rva:X}",
            "caller": caller_sym or f"main+0x{rva:X}",
        })
        if len(callers) >= max_results:
            break

    return json.dumps({
        "target": target_name,
        "target_offset": f"0x{target_off:X}",
        "total_callers": len(caller_rvas),
        "callers": callers,
    }, indent=2)


@mcp.tool()
@_safe_tool
def breeze_make_pointer_cheat(
    name: str,
    main_base_offset: str,
    offsets: list[str],
    value: float | int,
    dtype: str = "double",
) -> str:
    """Create an Atmosphere CheatVM Type 5 / 7 / 6 multi-level pointer dereference cheat.

    name: Cheat title, e.g. 'Max Money'
    main_base_offset: Hex offset in main (e.g. '0x234A3A0' or 'main+0x234A3A0')
    offsets: Hops to follow. Intermediate hops without '+' are dereferenced (580F1000).
             A hop starting with '+' (or final offset) is added to the pointer register (780F0000).
    value: Value to write (e.g. 99999.0)
    dtype: 'double' (8B IEEE-754), 'u64', 'u32', 'float'
    """
    base_str = main_base_offset.lower().replace("main+", "").replace("m+", "").strip()
    base_off = int(base_str, 16)

    lines = [f"[{name}]"]
    # 580F0000 <BASE_OFFSET>: Load 8-byte pointer from Main NSO into register F
    lines.append(f"580F0000 {base_off:08X}")

    for idx, raw_hop in enumerate(offsets):
        is_add_only = raw_hop.strip().startswith("+") or idx == len(offsets) - 1
        hop_val = int(raw_hop.strip().lstrip("+"), 16)
        if is_add_only:
            # 780F0000 <OFFSET>: Register F += OFFSET
            if hop_val != 0:
                lines.append(f"780F0000 {hop_val:08X}")
        else:
            # 580F1000 <OFFSET>: Register F = *(uint64_t*)(Register F + OFFSET)
            lines.append(f"580F1000 {hop_val:08X}")

    dt = dtype.lower().strip()
    if dt == "double":
        val_bytes = struct.pack("<d", float(value))
        hi, lo = struct.unpack(">II", val_bytes)
        # 680F0000 <HI32> <LO32>: Store 8-byte static value to [Register F]
        lines.append(f"680F0000 {hi:08X} {lo:08X}")
    elif dt == "u64":
        val_bytes = struct.pack("<Q", int(value))
        hi, lo = struct.unpack(">II", val_bytes)
        lines.append(f"680F0000 {hi:08X} {lo:08X}")
    elif dt in ("u32", "float"):
        fmt = "<f" if dt == "float" else "<I"
        val_bytes = struct.pack(fmt, float(value) if dt == "float" else int(value))
        val_word = struct.unpack(">I", val_bytes)[0]
        # 640F0000 <VAL32>: Store 4-byte static value to [Register F]
        lines.append(f"640F0000 {val_word:08X}")
    else:
        raise ValueError(f"Unsupported dtype '{dtype}'. Use double, u64, u32, or float.")

    return "\n".join(lines)


@mcp.tool()
@_safe_tool
def breeze_disassemble(offset_or_symbol: str, instruction_count: int = 60) -> str:
    """Disassemble ARM64 code from `main` using Capstone with symbol & ADRP resolution.

    offset_or_symbol: e.g. '0x7EA1E0', 'main+0x7EA1E0', or a symbol name like 'gml_Script_scr_stats_controller_update_stats'.
    """
    b = _get_client()
    meta = b.json("meta")
    main_base = int(meta["main"], 16)
    offsets, entries, name_to_off = _load_function_map(b)

    target_str = offset_or_symbol.strip()
    if target_str in name_to_off:
        start_off = name_to_off[target_str]
    else:
        addr = _parse_addr(b, target_str, meta)
        start_off = addr - main_base if addr >= main_base else addr

    byte_len = instruction_count * 4
    code_bytes = _read_chunked(b, main_base + start_off, byte_len)

    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    adrp_pages: dict[str, int] = {}
    out_lines = []

    fn_label = _resolve_symbol(offsets, entries, start_off)
    if fn_label:
        out_lines.append(f"; Function: {fn_label} (main+0x{start_off:X})")

    for insn in md.disasm(code_bytes, start_off):
        word_be = struct.unpack("<I", insn.bytes)[0]
        comment = ""

        # Track ADRP page for static data/BSS pointer discovery
        if insn.mnemonic == "adrp":
            parts = [p.strip() for p in insn.op_str.split(",")]
            if len(parts) == 2:
                reg, page_str = parts[0], parts[1].lstrip("#")
                try:
                    page_val = int(page_str, 0)
                    adrp_pages[reg] = page_val
                    comment = f" ; page=main+0x{page_val:X}"
                except ValueError:
                    pass
        elif insn.mnemonic in ("add", "ldr", "str") and adrp_pages:
            for reg, page_val in list(adrp_pages.items()):
                if reg in insn.op_str:
                    m_imm = re.search(r"#(0x[0-9a-fA-F]+|-?\d+)", insn.op_str)
                    if m_imm:
                        imm_val = int(m_imm.group(1), 0)
                        full_off = page_val + imm_val
                        sym = _resolve_symbol(offsets, entries, full_off)
                        comment = f" ; -> main+0x{full_off:X}" + (f" ({sym})" if sym else "")
                    break

        if insn.mnemonic in ("bl", "b"):
            target_str_op = insn.op_str.lstrip("#")
            try:
                call_off = int(target_str_op, 0)
                sym = _resolve_symbol(offsets, entries, call_off)
                if sym:
                    comment = f" ; {sym}"
            except ValueError:
                pass

        out_lines.append(f"main+0x{insn.address:06X}: {word_be:08X}  {insn.mnemonic:<8} {insn.op_str}{comment}")

    return "\n".join(out_lines)


@mcp.tool()
@_safe_tool
def breeze_make_asm_cheat(name: str, main_offset: str, patch: str) -> str:
    """Create an Atmosphere 04000000 ARM64 code patch cheat.

    main_offset: Hex offset from main (e.g. '0x1D3C80' or 'main+0x1D3C80').
    patch: Preset ('ret', 'nop', 'ret_true', 'ret_false', 'ret_zero', 'ret_one', 'ret_zero_double', 'ret_one_double', 'ret_struct_zero', 'yyc_ret_zero')
           OR custom ARM64 assembly instructions separated by ';' or newlines.
    """
    off_str = main_offset.lower().replace("main+", "").replace("m+", "").strip()
    off = int(off_str, 16)

    presets = {
        "ret": [0xD65F03C0],
        "nop": [0xD503201F],
        "ret_true": [0x52800020, 0xD65F03C0],      # mov w0, #1; ret (Unity/C++ bool true)
        "ret_false": [0x52800000, 0xD65F03C0],     # mov w0, #0; ret (Unity/C++ bool false)
        "ret_zero": [0x52800000, 0xD65F03C0],      # mov w0, #0; ret (32-bit int 0)
        "ret_one": [0x52800020, 0xD65F03C0],       # mov w0, #1; ret (32-bit int 1)
        "ret_zero_double": [0x1EE0001F, 0xD65F03C0],  # fmov d0, xzr; ret (double 0.0)
        "ret_one_double": [0x1E6E1000, 0xD65F03C0],   # fmov d0, #1.0; ret (double 1.0)
        "ret_struct_zero": [0xF900005F, 0xB9000C5F, 0xD65F03C0],  # zero out result pointer in x2 + ret
        "yyc_ret_zero": [0xF900005F, 0xB9000C5F, 0xD65F03C0],     # alias for ret_struct_zero (GameMaker YYC)
    }

    p_key = patch.strip().lower()
    if p_key in presets:
        words = presets[p_key]
    else:
        ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
        encoding, _ = ks.asm(patch, off)
        raw = bytes(encoding)
        if len(raw) % 4 != 0:
            raise ValueError(f"Assembled bytes length ({len(raw)}) is not a multiple of 4.")
        words = [struct.unpack("<I", raw[i:i + 4])[0] for i in range(0, len(raw), 4)]

    lines = [f"[{name}]"]
    for i, w in enumerate(words):
        lines.append(f"04000000 {off + i * 4:08X} {w:08X}")
    return "\n".join(lines)


@mcp.tool()
@_safe_tool
def breeze_deploy_cheats(cheats_block: str, activate: bool = True, save_to_sd: bool = True) -> str:
    """Add cheats to live Breeze dmnt and persist to both Breeze and Atmosphere SD card directories."""
    b = _get_client()
    meta = b.json("meta")
    tid = meta["title_id"].upper()
    bid = meta["build_id"].upper()

    added_ids = b.cheats_add(cheats_block, on=activate)

    sd_paths = []
    if save_to_sd:
        b.cmd("cheats save")
        # Read the saved Breeze cheat file and mirror it to Atmosphere contents
        breeze_cheat_path = f"sdmc:/switch/breeze/cheats/{tid}/{bid}.txt"
        atm_cheat_dir = f"sdmc:/atmosphere/contents/{tid}/cheats"
        atm_cheat_path = f"{atm_cheat_dir}/{bid}.txt"
        sd_paths.append(breeze_cheat_path)
        try:
            data = b.get_file(breeze_cheat_path)
            b.fs_do(f"mkdir {atm_cheat_dir}")
            b.fs_put(atm_cheat_path, 0, data)
            sd_paths.append(atm_cheat_path)
        except Exception as e:
            sd_paths.append(f"atmosphere_mirror_note: {e}")

    return json.dumps({
        "added_ids": added_ids,
        "activated": activate,
        "saved_paths": sd_paths,
    }, indent=2)


@mcp.tool()
@_safe_tool
def breeze_raw_cmd(command: str) -> str:
    """Execute any raw Breeze PC Connect command (e.g. 'holds', 'maps', 'cheats', 'prep', 'watch')."""
    b = _get_client()
    return str(b.cmd(command))


def get_client_config_paths() -> dict[str, str]:
    home = os.path.expanduser("~")
    is_win = sys.platform == "win32"
    is_mac = sys.platform == "darwin"

    paths = {}
    # Claude Desktop
    if is_mac:
        paths["claude"] = os.path.join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")
    elif is_win:
        appdata = os.environ.get("APPDATA", os.path.join(home, "AppData", "Roaming"))
        paths["claude"] = os.path.join(appdata, "Claude", "claude_desktop_config.json")
    else:
        paths["claude"] = os.path.join(home, ".config", "Claude", "claude_desktop_config.json")

    # Cursor
    paths["cursor"] = os.path.join(home, ".cursor", "mcp.json")

    # Antigravity / Gemini CLI
    paths["antigravity"] = os.path.join(home, ".gemini", "config", "mcp_config.json")

    # VS Code Cline
    if is_mac:
        paths["cline"] = os.path.join(home, "Library", "Application Support", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json")
    elif is_win:
        appdata = os.environ.get("APPDATA", os.path.join(home, "AppData", "Roaming"))
        paths["cline"] = os.path.join(appdata, "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json")
    else:
        paths["cline"] = os.path.join(home, ".config", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json")

    return paths


def install_cli(argv: list[str]) -> int:
    import argparse
    import shutil
    import socket

    parser = argparse.ArgumentParser(
        description="Install or configure the Breeze MCP server into Claude Desktop, Cursor, and Antigravity.",
        prog="breeze_mcp.py install"
    )
    parser.add_argument("--host", default=_DEFAULT_HOST, help=f"Switch IP address (default: {_DEFAULT_HOST})")
    parser.add_argument("--code", default=_DEFAULT_CODE, help=f"Breeze auth code (default: {_DEFAULT_CODE})")
    parser.add_argument("--client", choices=["all", "claude", "cursor", "antigravity", "cline"], default="all", help="Target AI client to configure")
    parser.add_argument("--uninstall", action="store_true", help="Remove Breeze MCP from client configs")
    parser.add_argument("--status", action="store_true", help="Show current installation status across clients")
    args = parser.parse_args(argv)

    client_paths = get_client_config_paths()
    script_path = os.path.abspath(__file__)
    uv_bin = shutil.which("uv")

    if uv_bin:
        exec_cmd = uv_bin
        exec_args = ["run", script_path]
    else:
        exec_cmd = sys.executable
        exec_args = [script_path]

    breeze_entry = {
        "command": exec_cmd,
        "args": exec_args,
        "env": {
            "BREEZE_HOST": args.host,
            "BREEZE_CODE": args.code,
        }
    }

    if args.status:
        print("\n=== Breeze MCP Installation Status ===")
        for name, path in client_paths.items():
            if not os.path.exists(path):
                print(f"  [-] {name.capitalize():<12} Config file not found ({path})")
                continue
            try:
                with open(path, "r", encoding="utf-8") as fp:
                    data = json.load(fp)
                servers = data.get("mcpServers", {})
                if "breeze" in servers:
                    cfg = servers["breeze"]
                    env = cfg.get("env", {})
                    print(f"  [✓] {name.capitalize():<12} INSTALLED -> Switch {env.get('BREEZE_HOST')}:{env.get('BREEZE_CODE')}")
                else:
                    print(f"  [ ] {name.capitalize():<12} Not installed (found {path})")
            except Exception as e:
                print(f"  [!] {name.capitalize():<12} Error reading config: {e}")
        return 0

    print(f"\n🎮 Breeze MCP Installer (Switch target: {args.host}, Auth code: {args.code})")
    print(f"   MCP Script: {script_path}")
    print(f"   Command:    {exec_cmd} {' '.join(exec_args)}\n")

    targets = list(client_paths.keys()) if args.client == "all" else [args.client]
    configured_count = 0

    for name in targets:
        path = client_paths[name]
        parent_dir = os.path.dirname(path)
        # For non-all installs or existing dirs, proceed
        if args.client == "all" and not os.path.exists(parent_dir):
            continue

        try:
            os.makedirs(parent_dir, exist_ok=True)
            data = {}
            if os.path.exists(path):
                try:
                    with open(path, "r", encoding="utf-8") as fp:
                        data = json.load(fp)
                except Exception:
                    data = {}

            if "mcpServers" not in data:
                data["mcpServers"] = {}

            if args.uninstall:
                if "breeze" in data["mcpServers"]:
                    del data["mcpServers"]["breeze"]
                    with open(path, "w", encoding="utf-8") as fp:
                        json.dump(data, fp, indent=2)
                    print(f"  [✓] Removed from {name.capitalize()} ({path})")
                    configured_count += 1
                else:
                    print(f"  [-] {name.capitalize()} did not have Breeze configured.")
            else:
                data["mcpServers"]["breeze"] = breeze_entry
                with open(path, "w", encoding="utf-8") as fp:
                    json.dump(data, fp, indent=2)
                print(f"  [✓] Configured {name.capitalize()} -> {path}")
                configured_count += 1
        except Exception as e:
            print(f"  [!] Failed to configure {name}: {e}")

    # Ping test
    if not args.uninstall:
        print("\nChecking connection to Nintendo Switch...")
        s = socket.socket()
        s.settimeout(2.5)
        try:
            s.connect((args.host, 6801))
            s.close()
            print(f"  [✓] Switch is reachable at {args.host}:6801! Connection verified.\n")
        except Exception as e:
            print(f"  [!] Notice: Switch at {args.host}:6801 did not answer ({e}).")
            print("      Ensure Breeze PC Connect is enabled in Settings > PC connect when using the MCP tools.\n")

    print(f"Done! {configured_count} client(s) updated.")
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ("install", "--install"):
        sys.exit(install_cli(sys.argv[2:]))
    elif len(sys.argv) > 1 and sys.argv[1] in ("status", "--status"):
        sys.exit(install_cli(["--status"]))
    elif len(sys.argv) > 1 and sys.argv[1] in ("uninstall", "--uninstall"):
        sys.exit(install_cli(["--uninstall"] + sys.argv[2:]))
    elif len(sys.argv) > 1 and sys.argv[1] == "--selftest":
        print("Running Breeze MCP selftest against Switch...")
        print(breeze_connect())
        print(breeze_search_functions("stats_controller"))
    elif len(sys.argv) >= 3 and sys.argv[1] == "--call":
        fn_name = sys.argv[2]
        kwargs = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
        fn = globals()[fn_name]
        print(fn(**kwargs))
    else:
        mcp.run()
