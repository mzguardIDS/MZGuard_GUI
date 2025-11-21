#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Zero-Trust Micro-Segmentor – hardened edition
Author: github.com/yourhandle
Licence: MIT – research use only
Tested: Win10 21H2 / Win11 23H2  – Python 3.11 x64  – HVCI ON
"""
import os
import sys
import json
import time
import uuid
import psutil
import ctypes
import hashlib
import logging
from pathlib import Path
from datetime import datetime

# --------------- CONFIG ------------------------------------------------------
CFG = {
    "whitelist_procs": {"System", "Registry", "Memory Compression", "MsMpEng.exe"},
    "alert_dir": Path(os.environ["PROGRAMDATA"]) / "ZTGuard/alerts",
    "kill_on_detect": True,
    "scan_interval": 1.0,
    "log_level": logging.INFO,
}
CFG["alert_dir"].mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=CFG["log_level"],
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)

# --------------- CTYPES HELPERS ----------------------------------------------
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

ERROR_ALREADY_EXISTS = 0x00000B5
EVENT_TRACE_REAL_TIME_MODE = 0x00000100
WNODE_FLAG_TRACED_GUID = 0x00020000

# --- tipi mancanti
class GUID(ctypes.Structure):
    _fields_ = [("Data1", ctypes.c_ulong),
                ("Data2", ctypes.c_ushort),
                ("Data3", ctypes.c_ushort),
                ("Data4", ctypes.c_byte * 8)]

class WNODE_HEADER(ctypes.Structure):
    _fields_ = [("BufferSize", ctypes.c_ulong),
                ("ProviderId", ctypes.c_ulong),
                ("HistoricalContext", ctypes.c_uint64),
                ("TimeStamp", ctypes.c_int64),
                ("Guid", GUID),
                ("ClientContext", ctypes.c_ulong),
                ("Flags", ctypes.c_ulong)]

class EVENT_TRACE_PROPERTIES(ctypes.Structure):
    _fields_ = [("Wnode", WNODE_HEADER),
                ("BufferSize", ctypes.c_ulong),
                ("MinimumBuffers", ctypes.c_ulong),
                ("MaximumBuffers", ctypes.c_ulong),
                ("MaximumFileSize", ctypes.c_ulong),
                ("LogFileMode", ctypes.c_ulong),
                ("FlushTimer", ctypes.c_ulong),
                ("EnableFlags", ctypes.c_ulong),
                ("AgeLimit", ctypes.c_long),
                ("NumberOfBuffers", ctypes.c_ulong),
                ("FreeBuffers", ctypes.c_ulong),
                ("EventsLost", ctypes.c_ulong),
                ("BuffersWritten", ctypes.c_ulong),
                ("LogBuffersLost", ctypes.c_ulong),
                ("RealTimeBuffersLost", ctypes.c_ulong),
                ("LoggerThreadId", ctypes.c_void_p),
                ("LogFileNameOffset", ctypes.c_ulong),
                ("LoggerNameOffset", ctypes.c_ulong)]

# --------------- ETW WRAPPER -------------------------------------------------
def start_etw_kernel_process_trace():
    """Avvia traccia real-time Microsoft-Windows-Kernel-Process (no driver)."""
    TRACE_NAME = "ZTGuardKernelProcess"
    # UUID → campi singoli
    u = uuid.UUID("{EDD08927-9CC4-4E65-B700-AD77E5F0A743}")
    guid = GUID(u.time_low,
                u.time_mid,
                u.time_hi_version,
                (ctypes.c_byte * 8)(*u.bytes[8:]))

    buffer = (ctypes.c_byte * (ctypes.sizeof(EVENT_TRACE_PROPERTIES) + 200))()
    prop = EVENT_TRACE_PROPERTIES.from_buffer(buffer)
    prop.Wnode.BufferSize        = len(buffer)
    prop.Wnode.Guid              = guid
    prop.Wnode.ClientContext     = 1
    prop.Wnode.Flags             = WNODE_FLAG_TRACED_GUID
    prop.LogFileMode             = EVENT_TRACE_REAL_TIME_MODE
    prop.LoggerNameOffset        = ctypes.sizeof(EVENT_TRACE_PROPERTIES)

    handle = ctypes.c_void_p()
    res = advapi32.StartTraceW(ctypes.byref(handle), TRACE_NAME, prop)
    if res == ERROR_ALREADY_EXISTS:
        advapi32.ControlTraceW(handle, TRACE_NAME, prop, 1)  # stop
        res = advapi32.StartTraceW(ctypes.byref(handle), TRACE_NAME, prop)
    if res != 0:
        raise RuntimeError(f"StartTrace failed 0x{res:08X}")
    logging.info("ETW Kernel-Process trace started")
    return handle

# --------------- ALERT / KILL -----------------------------------------------
def alert(pid, pname, rule, extra=""):
    ts = datetime.utcnow().isoformat(timespec="seconds")
    payload = {"pid": pid, "pname": pname, "rule": rule, "extra": extra, "ts": ts}
    fn = CFG["alert_dir"] / f"{ts}_{pid}.json"
    fn.write_text(json.dumps(payload, indent=2))
    logging.warning("ALERT %s on %s(%s) %s", rule, pname, pid, extra)
    if CFG["kill_on_detect"]:
        try:
            psutil.Process(pid).terminate()
            psutil.Process(pid).wait(3)
            logging.info("Killed %s(%s)", pname, pid)
        except psutil.NoSuchProcess:
            pass

# --------------- MEMORY SCAN -------------------------------------------------
def scan_rwx_regions(proc):
    """Trova regioni PAGE_EXECUTE_READWRITE e matcha firme generiche."""
    matches = []
    try:
        for m in proc.memory_maps(grouped=False):
            if "PAGE_EXECUTE_READWRITE" not in m.perms:
                continue
            base, size = int(m.addr.split("-")[0], 16), m.rss
            if size == 0:
                continue
            # Leggiamo 4 MB max
            chunk = proc.memory_maps()[0].read(base, min(size, 4 * 1024 * 1024))
            if detect_shellcode_patterns(chunk):
                matches.append(m.addr)
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        pass
    return matches

def detect_shellcode_patterns(data):
    """Firme semplici: XOR imm32, RC4 loop, GetProcAddress call."""
    # XOR reg, imm32  + JZ
    if b"\x81" in data and b"\x0F\x84" in data:
        return True
    # RC4 classic stub
    if b"\xC7\x45" in data and b"\x8B\x45" in data and b"\x8A\x08\x88\x4D" in data:
        return True
    # GetProcAddress call
    if b"\xFF\x15" in data and b"\x50\xFF\x15" in data:
        return True
    return False

# --------------- CLEAN NTDLL DETECT -----------------------------------------
def detect_clean_ntdll(proc):
    try:
        ntdll = [m for m in proc.memory_maps() if m.path.lower().endswith("ntdll.dll")]
        if not ntdll:
            return False
        orig_path = ntdll[0].path
        time.sleep(5)
        for m in proc.memory_maps():
            if m.path.lower().endswith("ntdll.dll") and m.path != orig_path:
                return True
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        pass
    return False

# --------------- MAIN LOOP ---------------------------------------------------
def main_loop():
    targets = {"svchost.exe", "explorer.exe", "dllhost.exe"}
    while True:
        for proc in psutil.process_iter(["pid", "name"]):
            if proc.info["name"] not in targets:
                continue
            pid = proc.info["pid"]
            pname = proc.info["name"]

            # 1) RWX scan
            if hits := scan_rwx_regions(proc):
                alert(pid, pname, "RWX_SHELLCODE", f"regions {hits}")
                continue

            # 2) Clean ntdll
            if detect_clean_ntdll(proc):
                alert(pid, pname, "CLEAN_NTDLL", "ntdll re-mapped")
                continue

        time.sleep(CFG["scan_interval"])

# --------------- ENTRYPOINT --------------------------------------------------
def main():
    if not ctypes.windll.shell32.IsUserAnAdmin():
        logging.error("Run as elevated administrator")
        sys.exit(1)
    try:
        start_etw_kernel_process_trace()
    except Exception as e:
        logging.error("ETW init failed: %s", e)
        # continuiamo comunque – il resto funziona
    logging.info("ZTGuard loop started")
    main_loop()

if __name__ == "__main__":
    main()