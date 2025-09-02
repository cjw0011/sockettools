#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Socket Test Tool v1.3.0
- Graceful server stop for TCP/UDP (stop_event + close() + join())
- Client tester (ACK/NACK), optional no TIME_WAIT
- Windows NIC config (static/DHCP)
- Robust interface discovery via PowerShell JSON
- UTF-8 enforced subprocess I/O (fix GBK decode errors)
- Friendly matching/logging: tolerate CR/LF differences, show UTF-8 preview
- NEW: Ping module (GUI + CLI) with RTT stats
"""

from __future__ import annotations

import argparse
import json
import locale
import platform
import re
import socket
import struct
import subprocess
import sys
import threading
import time
from typing import List, Tuple, Optional

# ==== Tkinter GUI ====
try:
    import tkinter as tk
    from tkinter import ttk
    from tkinter.scrolledtext import ScrolledText
    GUI_AVAILABLE = True
except Exception:
    GUI_AVAILABLE = False


# =========================
# Utilities
# =========================
def parse_ports(ports_str: str) -> List[int]:
    result: List[int] = []
    for part in ports_str.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            start = int(a)
            end = int(b)
            if start > end:
                start, end = end, start
            result.extend(range(start, end + 1))
        else:
            result.append(int(part))
    return sorted(set([p for p in result if 1 <= p <= 65535]))


def current_ts() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def is_windows() -> bool:
    return platform.system().lower().startswith("win")


# =========================
# Subprocess helpers (UTF-8 enforced)
# =========================
def run_cmd(cmd: List[str], timeout: int = 30, encoding: Optional[str] = None) -> Tuple[int, str]:
    """
    统一子进程执行：按指定编码解码，默认根据平台动态选择并容错。
    Windows 下改用 OEM 代码页以避免 netsh 等命令输出中文接口名时乱码。
    """
    if encoding is None:
        encoding = "oem" if is_windows() else "utf-8"
    try:
        try:
            p = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding=encoding,
                errors="replace",
                shell=False,
            )
        except LookupError:
            # 某些平台可能不支持 "oem"，回退到本地默认编码
            fallback = locale.getpreferredencoding(False) if is_windows() else "utf-8"
            p = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding=fallback,
                errors="replace",
                shell=False,
            )
        out, _ = p.communicate(timeout=timeout)
        return p.returncode, (out or "").strip()
    except Exception as e:
        return 1, f"ERR running {' '.join(cmd)}: {e}"


def run_powershell_json(ps_script: str, timeout: int = 30) -> Tuple[int, list]:
    """
    以 PowerShell 执行脚本并 ConvertTo-Json，返回 Python 对象（list 或单对象列表）。
    强制将 PowerShell 输出编码设置为 UTF-8，适配中文/英文环境。
    """
    if not is_windows():
        return 1, []

    ps_prefix = (
        r"[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;"
        r"$OutputEncoding=[System.Text.Encoding]::UTF8;"
        r"$PSStyle.OutputRendering='PlainText';"
    )
    cmd = [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        f"{ps_prefix} {ps_script} | ConvertTo-Json -Compress",
    ]
    code, out = run_cmd(cmd, timeout=timeout, encoding="utf-8")
    if code != 0 or not out:
        return 1, []

    try:
        data = json.loads(out)
        return 0, data if isinstance(data, list) else [data]
    except Exception:
        try:
            cleaned = out.encode("utf-8", "ignore").decode("utf-8", "ignore").strip()
            data = json.loads(cleaned) if cleaned else []
            return 0, data if isinstance(data, list) else [data]
        except Exception:
            return 1, []


def list_windows_interfaces() -> List[str]:
    """
    稳定获取 Windows 接口名：
    1) Get-NetAdapter（过滤 Disabled）
    2) Get-CimInstance Win32_NetworkAdapter（NetEnabled=true）
    3) netsh interface ipv4 show interfaces 正则兜底
    """
    names: List[str] = []

    # 1) Get-NetAdapter
    code, data = run_powershell_json(
        r"Get-NetAdapter | Where-Object {$_.Status -ne 'Disabled'} | Select-Object -ExpandProperty Name"
    )
    if code == 0 and data:
        for item in data:
            if isinstance(item, str) and item.strip():
                names.append(item.strip())

    # 2) CIM 兜底
    if not names:
        code, data = run_powershell_json(
            r"Get-CimInstance -ClassName Win32_NetworkAdapter -Filter 'NetEnabled=true' | Select-Object -ExpandProperty Name"
        )
        if code == 0 and data:
            for item in data:
                if isinstance(item, str) and item.strip():
                    names.append(item.strip())

    # 3) netsh 兜底
    if not names:
        code, out = run_cmd(["netsh", "interface", "ipv4", "show", "interfaces"], encoding=None)
        if code == 0 and out:
            for line in out.splitlines():
                line = line.strip()
                if not line or re.search(r"(Idx|Met|MTU|状态|State)", line, re.I):
                    continue
                m = re.match(r"^\s*\d+\s+\d+\s+\d+\s+\S+\s+(.+)$", line)
                if m:
                    names.append(m.group(1).strip())

    seen = set()
    uniq: List[str] = []
    for n in names:
        if n not in seen:
            seen.add(n)
            uniq.append(n)
    return uniq


# =========================
# Server impl with graceful stop
# =========================
class ServerHandle:
    def __init__(self, thread: threading.Thread, sock: socket.socket, proto: str, bind_ip: str, port: int):
        self.thread = thread
        self.sock = sock
        self.proto = proto
        self.bind_ip = bind_ip
        self.port = port


class ServerManager:
    def __init__(self, log_func):
        self.log = log_func
        self.stop_event = threading.Event()
        self.handles: List[ServerHandle] = []
        self._lock = threading.Lock()

    def start(self, bind_ip: str, ports: List[int], proto: str, message: bytes):
        with self._lock:
            self.stop_event.clear()
            self.handles.clear()

            if proto in ("tcp", "both"):
                for p in ports:
                    h = self._start_tcp(bind_ip, p, message)
                    self.handles.append(h)
            if proto in ("udp", "both"):
                for p in ports:
                    h = self._start_udp(bind_ip, p, message)
                    self.handles.append(h)
        if self.handles:
            self.log(f"[{current_ts()}] [Server] Started {len(self.handles)} listener(s).")

    def stop(self):
        with self._lock:
            if not self.handles:
                self.log(f"[{current_ts()}] [Server] Not running.")
                return
            self.stop_event.set()
            for h in self.handles:
                try:
                    h.sock.close()
                except Exception:
                    pass
            for h in self.handles:
                try:
                    h.thread.join(timeout=2.0)
                except Exception:
                    pass
            n = len(self.handles)
            self.handles.clear()
            self.log(f"[{current_ts()}] [Server] Cleanly stopped {n} listener(s).")

    def _start_tcp(self, bind_ip: str, port: int, message: bytes) -> ServerHandle:
        def run(server_sock: socket.socket):
            try:
                server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server_sock.bind((bind_ip, port))
                server_sock.listen(128)
                server_sock.settimeout(0.5)
                self.log(f"[{current_ts()}] [TCP] Listening on {bind_ip}:{port}")
                while not self.stop_event.is_set():
                    try:
                        client_sock, addr = server_sock.accept()
                    except socket.timeout:
                        continue
                    except OSError:
                        break
                    t = threading.Thread(
                        target=self._handle_tcp_client, args=(client_sock, addr, message), daemon=True
                    )
                    t.start()
            except Exception as e:
                self.log(f"[{current_ts()}] [TCP {bind_ip}:{port}] Error: {e}")
            finally:
                try:
                    server_sock.close()
                except Exception:
                    pass
                self.log(f"[{current_ts()}] [TCP] Stopped {bind_ip}:{port}")

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        th = threading.Thread(target=run, args=(s,), daemon=False)
        th.start()
        return ServerHandle(th, s, "tcp", bind_ip, port)

    def _handle_tcp_client(self, client_sock: socket.socket, addr: Tuple[str, int], message: bytes):
        def _preview(b: bytes, maxn: int = 64) -> str:
            txt = b.decode("utf-8", "replace")
            if len(txt) > maxn:
                txt = txt[:maxn] + "…"
            return txt

        try:
            client_sock.settimeout(5.0)
            data = client_sock.recv(4096)

            expected = message
            ack = (
                data == expected
                or data.strip(b"\r\n") == expected
                or data == expected.strip(b"\r\n")
            )

            if ack:
                client_sock.sendall(b"ACK")
                self.log(f"[{current_ts()}] [TCP] {addr} => ACK | recv='{_preview(data)}' len={len(data)}")
            else:
                client_sock.sendall(b"NACK")
                self.log(f"[{current_ts()}] [TCP] {addr} => NACK | recv='{_preview(data)}' len={len(data)}")
        except socket.timeout:
            self.log(f"[{current_ts()}] [TCP] {addr} recv timeout")
        except Exception as e:
            self.log(f"[{current_ts()}] [TCP] {addr} error: {e}")
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

    def _start_udp(self, bind_ip: str, port: int, message: bytes) -> ServerHandle:
        def run(server_sock: socket.socket):
            def _preview(b: bytes, maxn: int = 64) -> str:
                txt = b.decode("utf-8", "replace")
                if len(txt) > maxn:
                    txt = txt[:maxn] + "…"
                return txt

            try:
                server_sock.bind((bind_ip, port))
                server_sock.settimeout(0.5)
                self.log(f"[{current_ts()}] [UDP] Listening on {bind_ip}:{port}")
                while not self.stop_event.is_set():
                    try:
                        data, addr = server_sock.recvfrom(4096)
                    except socket.timeout:
                        continue
                    except OSError:
                        break

                    expected = message
                    ack = (
                        data == expected
                        or data.strip(b"\r\n") == expected
                        or data == expected.strip(b"\r\n")
                    )

                    try:
                        if ack:
                            server_sock.sendto(b"ACK", addr)
                            self.log(f"[{current_ts()}] [UDP] {addr} => ACK | recv='{_preview(data)}' len={len(data)}")
                        else:
                            server_sock.sendto(b"NACK", addr)
                            self.log(f"[{current_ts()}] [UDP] {addr} => NACK | recv='{_preview(data)}' len={len(data)}")
                    except Exception as e:
                        self.log(f"[{current_ts()}] [UDP] send error: {e}")
            except Exception as e:
                self.log(f"[{current_ts()}] [UDP {bind_ip}:{port}] Error: {e}")
            finally:
                try:
                    server_sock.close()
                except Exception:
                    pass
                self.log(f"[{current_ts()}] [UDP] Stopped {bind_ip}:{port}")

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        th = threading.Thread(target=run, args=(s,), daemon=False)
        th.start()
        return ServerHandle(th, s, "udp", bind_ip, port)


# =========================
# Client impl
# =========================
def tcp_client_test(
    target_ip: str, port: int, payload: bytes, timeout: float = 5.0, no_time_wait: bool = False
) -> Tuple[bool, str]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        if no_time_wait:
            linger = struct.pack("hh", 1, 0)  # on=1, timeout=0 -> 发送 RST（仅测试）
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)
        sock.connect((target_ip, port))
        sock.sendall(payload)
        data = sock.recv(4096)
        ok = data == b"ACK"
        return ok, (data.decode(errors="ignore") if data else "")
    except Exception as e:
        return False, f"ERR: {e}"
    finally:
        try:
            sock.close()
        except Exception:
            pass


def udp_client_test(target_ip: str, port: int, payload: bytes, timeout: float = 5.0) -> Tuple[bool, str]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(payload, (target_ip, port))
        data, _ = sock.recvfrom(4096)
        ok = data == b"ACK"
        return ok, (data.decode(errors="ignore") if data else "")
    except Exception as e:
        return False, f"ERR: {e}"
    finally:
        try:
            sock.close()
        except Exception:
            pass


# =========================
# Ping module
# =========================
def ping_host(host: str, count: int = 4, timeout_ms: int = 1000, interval_ms: int = 1000) -> Tuple[bool, str]:
    """
    跨平台 ping：
    - Windows: ping -n COUNT -w TIMEOUT_MS
    - Linux/mac: ping -c COUNT -W TIMEOUT_S -i INTERVAL_S
    返回 (ok, summary_text)
    """
    host = host.strip()
    if not host:
        return False, "Ping: host 不能为空。"

    sysname = platform.system().lower()
    if "windows" in sysname:
        cmd = ["ping", "-n", str(count), "-w", str(int(timeout_ms)), host]
        # Windows 无 -i 自定义间隔，默认 1s
    else:
        # -W 的单位多为秒；interval 不能太小（<0.2 一般需要 root）
        t_s = max(1, int(round(timeout_ms / 1000.0)))
        i_s = max(0.2, round(interval_ms / 1000.0, 2))
        cmd = ["ping", "-c", str(count), "-W", str(t_s), "-i", str(i_s), host]

    code, out = run_cmd(cmd, timeout=max(10, count * 5), encoding=None)
    if code != 0 and not out:
        return False, f"Ping 执行失败（{code}）。"

    # 解析 RTT；兼容中英文：time= / 时间= / 时间<1ms
    times: List[float] = []
    for line in out.splitlines():
        m = re.search(r"(?i)(time|时间)\s*[=<]\s*([\d\.]+)\s*ms", line)
        if m:
            try:
                times.append(float(m.group(2)))
            except Exception:
                pass

    sent = count
    recv = len(times)
    loss = max(0, min(100, int(round((sent - recv) * 100.0 / sent)))) if sent else 100
    if times:
        mn = min(times)
        mx = max(times)
        avg = sum(times) / len(times)
        stats = f"RTT(ms) min/avg/max = {mn:.1f}/{avg:.1f}/{mx:.1f}"
    else:
        stats = "RTT(ms) 无"

    ok = recv > 0 and loss < 100
    summary = (
        f"[Ping] host={host} count={count} timeout={timeout_ms}ms interval={interval_ms}ms\n"
        f"[Ping] sent={sent} recv={recv} loss={loss}% | {stats}\n"
        f"[Ping] raw output:\n{out}"
    )
    return ok, summary


# =========================
# NIC configuration (Windows-first)
# =========================
def mask_to_cidr(mask: str) -> int:
    try:
        parts = [int(x) for x in mask.split(".")]
        b = "".join(f"{p:08b}" for p in parts)
        return b.count("1")
    except Exception:
        return 24


def windows_set_static(
    interface: str, ip: str, mask: str, gateway: Optional[str], dns1: Optional[str], dns2: Optional[str]
) -> Tuple[bool, str]:
    cmd_addr = [
        "netsh", "interface", "ipv4", "set", "address",
        f"name={interface}", "static", ip, mask
    ] + ([gateway, "1"] if gateway else [])
    code, out = run_cmd(cmd_addr, encoding=None)
    if code != 0:
        return False, out or "failed: set address"

    run_cmd(["netsh", "interface", "ipv4", "delete", "dnsservers", f"name={interface}", "all"], encoding=None)
    if dns1:
        code, out1 = run_cmd([
            "netsh", "interface", "ipv4", "add", "dnsservers",
            f"name={interface}", f"address={dns1}", "index=1", "validate=no"
        ], encoding=None)
        if code != 0:
            return False, out1 or "failed: add dns1"
    if dns2:
        code, out2 = run_cmd([
            "netsh", "interface", "ipv4", "add", "dnsservers",
            f"name={interface}", f"address={dns2}", "index=2", "validate=no"
        ], encoding=None)
        if code != 0:
            return False, out2 or "failed: add dns2"
    return True, "OK"


def windows_set_dhcp(interface: str) -> Tuple[bool, str]:
    ok1, out1 = run_cmd([
        "netsh", "interface", "ipv4", "set", "address", f"name={interface}", "source=dhcp"
    ], encoding=None)
    ok2, out2 = run_cmd([
        "netsh", "interface", "ipv4", "set", "dnsservers", f"name={interface}", "source=dhcp"
    ], encoding=None)
    if ok1 == 0 and ok2 == 0:
        return True, "OK"
    return False, (out1 or "") + "\n" + (out2 or "")


def linux_set_static(
    interface: str, ip: str, mask: str, gateway: Optional[str], dns1: Optional[str], dns2: Optional[str]
) -> Tuple[bool, str]:
    msg = (
        "Linux/macOS 请以管理员方式在终端执行：\n"
        f"sudo ip addr flush dev {interface}\n"
        f"sudo ip addr add {ip}/{mask_to_cidr(mask)} dev {interface}\n"
        + (f"sudo ip route add default via {gateway}\n" if gateway else "")
        + (f'echo "nameserver {dns1}\\nnameserver {dns2 or ""}" | sudo tee /etc/resolv.conf\n' if dns1 else "")
    )
    return False, msg


def linux_set_dhcp(interface: str) -> Tuple[bool, str]:
    return False, "Linux/macOS 建议使用 NetworkManager（nmcli）或 systemsetup（macOS），此工具暂不直接修改。"


# =========================
# GUI
# =========================
class SocketToolGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Socket Test Tool (TCP/UDP) — 端口优雅关闭 + NIC + Ping")
        self.root.geometry("1000x820")

        self.log_text = ScrolledText(self.root, height=18, wrap="word")
        self.log_text.configure(state="disabled")

        # ---- Server/Client ----
        netfrm = ttk.LabelFrame(self.root, text="Server / Client")
        ttk.Label(netfrm, text="Bind IP:").grid(row=0, column=0, sticky="e", padx=4, pady=4)
        self.bind_ip_var = tk.StringVar(value="0.0.0.0")
        ttk.Entry(netfrm, textvariable=self.bind_ip_var, width=18).grid(row=0, column=1, sticky="w", padx=4, pady=4)

        ttk.Label(netfrm, text="Ports (e.g. 8000,8001-8003):").grid(row=0, column=2, sticky="e", padx=4, pady=4)
        self.ports_var = tk.StringVar(value="8000")
        ttk.Entry(netfrm, textvariable=self.ports_var, width=28).grid(row=0, column=3, sticky="w", padx=4, pady=4)

        ttk.Label(netfrm, text="Protocol:").grid(row=0, column=4, sticky="e", padx=4, pady=4)
        self.proto_var = tk.StringVar(value="both")
        ttk.Combobox(netfrm, textvariable=self.proto_var, values=["tcp", "udp", "both"], width=6, state="readonly").grid(
            row=0, column=5, sticky="w", padx=4, pady=4
        )

        ttk.Label(netfrm, text="Message:").grid(row=1, column=0, sticky="e", padx=4, pady=4)
        self.msg_var = tk.StringVar(value="test")
        ttk.Entry(netfrm, textvariable=self.msg_var, width=18).grid(row=1, column=1, sticky="w", padx=4, pady=4)

        ttk.Label(netfrm, text="Target IP (Client):").grid(row=1, column=2, sticky="e", padx=4, pady=4)
        self.target_ip_var = tk.StringVar(value="127.0.0.1")
        ttk.Entry(netfrm, textvariable=self.target_ip_var, width=28).grid(row=1, column=3, sticky="w", padx=4, pady=4)

        self.no_time_wait_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(netfrm, text="TCP no TIME_WAIT (test only)", variable=self.no_time_wait_var).grid(
            row=1, column=4, columnspan=2, sticky="w", padx=4, pady=4
        )

        btnfrm = ttk.Frame(netfrm)
        ttk.Button(btnfrm, text="Start Server", command=self.start_server).grid(row=0, column=0, padx=6, pady=6)
        ttk.Button(btnfrm, text="Stop Server", command=self.stop_server).grid(row=0, column=1, padx=6, pady=6)
        ttk.Button(btnfrm, text="Client Test", command=self.client_test).grid(row=0, column=2, padx=6, pady=6)
        ttk.Button(btnfrm, text="Clear Log", command=lambda: self._set_log("", replace=True)).grid(row=0, column=3, padx=6, pady=6)
        btnfrm.grid(row=2, column=0, columnspan=6, sticky="w")

        netfrm.pack(fill="x", padx=6, pady=6)

        # ---- Ping ----
        pingfrm = ttk.LabelFrame(self.root, text="Ping")
        ttk.Label(pingfrm, text="Host/IP:").grid(row=0, column=0, sticky="e", padx=4, pady=4)
        self.ping_host_var = tk.StringVar(value="127.0.0.1")
        ttk.Entry(pingfrm, textvariable=self.ping_host_var, width=24).grid(row=0, column=1, sticky="w", padx=4, pady=4)

        ttk.Label(pingfrm, text="Count:").grid(row=0, column=2, sticky="e", padx=4, pady=4)
        self.ping_count_var = tk.StringVar(value="4")
        ttk.Entry(pingfrm, textvariable=self.ping_count_var, width=8).grid(row=0, column=3, sticky="w", padx=4, pady=4)

        ttk.Label(pingfrm, text="Timeout(ms):").grid(row=0, column=4, sticky="e", padx=4, pady=4)
        self.ping_timeout_var = tk.StringVar(value="1000")
        ttk.Entry(pingfrm, textvariable=self.ping_timeout_var, width=10).grid(row=0, column=5, sticky="w", padx=4, pady=4)

        ttk.Label(pingfrm, text="Interval(ms):").grid(row=0, column=6, sticky="e", padx=4, pady=4)
        self.ping_interval_var = tk.StringVar(value="1000")
        ttk.Entry(pingfrm, textvariable=self.ping_interval_var, width=10).grid(row=0, column=7, sticky="w", padx=4, pady=4)

        ttk.Button(pingfrm, text="Ping", command=self.ping_action).grid(row=0, column=8, padx=8, pady=4)

        pingfrm.pack(fill="x", padx=6, pady=6)

        # ---- NIC ----
        nicfrm = ttk.LabelFrame(self.root, text="NIC 配置（Windows 需管理员运行）")
        ttk.Label(nicfrm, text="接口名:").grid(row=0, column=0, sticky="e", padx=4, pady=4)
        self.nic_name_var = tk.StringVar(value="")
        self.nic_combo = ttk.Combobox(nicfrm, textvariable=self.nic_name_var, values=[], width=30)
        self.nic_combo.grid(row=0, column=1, sticky="w", padx=4, pady=4)
        ttk.Button(nicfrm, text="刷新接口列表", command=self.refresh_interfaces).grid(row=0, column=2, padx=6, pady=4)

        ttk.Label(nicfrm, text="IP 地址:").grid(row=1, column=0, sticky="e", padx=4, pady=4)
        self.ip_var = tk.StringVar(value="")
        ttk.Entry(nicfrm, textvariable=self.ip_var, width=18).grid(row=1, column=1, sticky="w", padx=4, pady=4)

        ttk.Label(nicfrm, text="子网掩码:").grid(row=1, column=2, sticky="e", padx=4, pady=4)
        self.mask_var = tk.StringVar(value="255.255.255.0")
        ttk.Entry(nicfrm, textvariable=self.mask_var, width=18).grid(row=1, column=3, sticky="w", padx=4, pady=4)

        ttk.Label(nicfrm, text="网关:").grid(row=1, column=4, sticky="e", padx=4, pady=4)
        self.gw_var = tk.StringVar(value="")
        ttk.Entry(nicfrm, textvariable=self.gw_var, width=18).grid(row=1, column=5, sticky="w", padx=4, pady=4)

        ttk.Label(nicfrm, text="DNS1:").grid(row=2, column=0, sticky="e", padx=4, pady=4)
        self.dns1_var = tk.StringVar(value="")
        ttk.Entry(nicfrm, textvariable=self.dns1_var, width=18).grid(row=2, column=1, sticky="w", padx=4, pady=4)

        ttk.Label(nicfrm, text="DNS2:").grid(row=2, column=2, sticky="e", padx=4, pady=4)
        self.dns2_var = tk.StringVar(value="")
        ttk.Entry(nicfrm, textvariable=self.dns2_var, width=18).grid(row=2, column=3, sticky="w", padx=4, pady=4)

        ttk.Button(nicfrm, text="应用静态配置", command=self.apply_static).grid(row=3, column=0, padx=6, pady=6)
        ttk.Button(nicfrm, text="切换为 DHCP", command=self.apply_dhcp).grid(row=3, column=1, padx=6, pady=6)

        nicfrm.pack(fill="x", padx=6, pady=6)

        self.log_text.pack(fill="both", expand=True, padx=6, pady=6)

        self.server_mgr = ServerManager(self.log)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.refresh_interfaces()

    # ---------- logging ----------
    def log(self, s: str):
        self._set_log(s + "\n", replace=False)

    def _set_log(self, s: str, replace: bool = False):
        self.log_text.configure(state="normal")
        if replace:
            self.log_text.delete("1.0", "end")
            self.log_text.insert("end", s)
        else:
            self.log_text.insert("end", s)
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    # ---------- server/client ----------
    def start_server(self):
        bind_ip = self.bind_ip_var.get().strip()
        ports = parse_ports(self.ports_var.get())
        proto = self.proto_var.get()
        message = self.msg_var.get().encode()

        if not ports:
            self.log(f"[{current_ts()}] [Server] Invalid ports.")
            return

        self.server_mgr.start(bind_ip, ports, proto, message)

    def stop_server(self):
        self.server_mgr.stop()

    def client_test(self):
        target_ip = self.target_ip_var.get().strip()
        ports = parse_ports(self.ports_var.get())
        proto = self.proto_var.get()
        message = self.msg_var.get().encode()
        no_time_wait = self.no_time_wait_var.get()

        if not ports:
            self.log(f"[{current_ts()}] [Client] Invalid ports.")
            return

        def run():
            total = 0
            ok_cnt = 0
            if proto in ("tcp", "both"):
                for p in ports:
                    total += 1
                    ok, resp = tcp_client_test(target_ip, p, message, timeout=5.0, no_time_wait=no_time_wait)
                    self.log(f"[{current_ts()}] [Client TCP {target_ip}:{p}] => {resp if resp else ok}")
                    if ok:
                        ok_cnt += 1
            if proto in ("udp", "both"):
                for p in ports:
                    total += 1
                    ok, resp = udp_client_test(target_ip, p, message, timeout=5.0)
                    self.log(f"[{current_ts()}] [Client UDP {target_ip}:{p}] => {resp if resp else ok}")
                    if ok:
                        ok_cnt += 1
            self.log(f"[{current_ts()}] [Client] Done: {ok_cnt}/{total} OK.")

        t = threading.Thread(target=run, daemon=True)
        t.start()

    # ---------- ping ----------
    def ping_action(self):
        host = self.ping_host_var.get().strip()
        try:
            count = int(self.ping_count_var.get().strip())
            timeout_ms = int(self.ping_timeout_var.get().strip())
            interval_ms = int(self.ping_interval_var.get().strip())
        except Exception:
            self.log("[Ping] 参数错误。")
            return

        def run():
            ok, summary = ping_host(host, count=count, timeout_ms=timeout_ms, interval_ms=interval_ms)
            for line in summary.splitlines():
                self.log(line)

        threading.Thread(target=run, daemon=True).start()

    def on_close(self):
        try:
            self.server_mgr.stop()
        finally:
            self.root.destroy()

    def run(self):
        self.root.mainloop()

    # ---------- NIC config ----------
    def refresh_interfaces(self):
        if not is_windows():
            self.nic_combo["values"] = []
            self.log("[NIC] 当前 OS 不是 Windows，界面仅做展示。请在 Linux/macOS 上使用系统网络管理工具修改 IP。")
            return
        names = list_windows_interfaces()
        self.nic_combo["values"] = names
        if names and not self.nic_name_var.get():
            self.nic_name_var.set(names[0])
        self.log(f"[NIC] 检测到接口：{', '.join(names) if names else '（无）'}")

    def apply_static(self):
        name = self.nic_name_var.get().strip()
        ip = self.ip_var.get().strip()
        mask = self.mask_var.get().strip()
        gw = self.gw_var.get().strip() or None
        dns1 = self.dns1_var.get().strip() or None
        dns2 = self.dns2_var.get().strip() or None

        if not name or not ip or not mask:
            self.log("[NIC] 接口名/IP/掩码 不能为空。")
            return

        if is_windows():
            ok, out = windows_set_static(name, ip, mask, gw, dns1, dns2)
        else:
            ok, out = linux_set_static(name, ip, mask, gw, dns1, dns2)
        if ok:
            self.log(f"[NIC] 已应用静态配置：{name} -> {ip}/{mask} gw={gw or '-'} dns={dns1 or '-'} {dns2 or ''}")
        else:
            self.log(f"[NIC] 失败：\n{out}\n（Windows 请以管理员身份运行）")

    def apply_dhcp(self):
        name = self.nic_name_var.get().strip()
        if not name:
            self.log("[NIC] 接口名不能为空。")
            return
        if is_windows():
            ok, out = windows_set_dhcp(name)
        else:
            ok, out = linux_set_dhcp(name)
        if ok:
            self.log(f"[NIC] {name} 已切换为 DHCP。")
        else:
            self.log(f"[NIC] 失败：\n{out}\n（Windows 请以管理员身份运行）")


# =========================
# CLI
# =========================
def run_cli(args):
    def log(s: str):
        print(s, flush=True)

    # ping
    if args.mode == "ping":
        ok, summary = ping_host(args.host, count=args.count, timeout_ms=args.timeout, interval_ms=args.interval)
        print(summary)
        return 0 if ok else 2

    # NIC
    if args.mode == "nic":
        if args.nic_action == "list":
            if not is_windows():
                print("当前 OS 不是 Windows。Linux/macOS 请使用系统工具。")
                return 0
            names = list_windows_interfaces()
            print("\n".join(names) if names else "(无)")
            return 0

        if args.nic_action == "static":
            if is_windows():
                ok, out = windows_set_static(args.name, args.ip, args.mask, args.gateway, args.dns1, args.dns2)
            else:
                ok, out = linux_set_static(args.name, args.ip, args.mask, args.gateway, args.dns1, args.dns2)
            print("OK" if ok else out)
            return 0 if ok else 2

        if args.nic_action == "dhcp":
            if is_windows():
                ok, out = windows_set_dhcp(args.name)
            else:
                ok, out = linux_set_dhcp(args.name)
            print("OK" if ok else out)
            return 0 if ok else 2

        print("Unknown NIC action")
        return 2

    # Server/Client
    mgr = ServerManager(log)

    if args.mode == "server":
        bind_ip = args.bind_ip
        ports = parse_ports(args.ports)
        proto = args.proto
        message = args.message.encode()

        if not ports:
            log("[Server] Invalid ports.")
            return 2

        mgr.start(bind_ip, ports, proto, message)
        log("[Server] Press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            log("[Server] Stopping...")
            mgr.stop()
        return 0

    elif args.mode == "client":
        target_ip = args.target_ip
        ports = parse_ports(args.ports)
        proto = args.proto
        message = args.message.encode()
        no_time_wait = args.no_time_wait

        if not ports:
            log("[Client] Invalid ports.")
            return 2

        total = 0
        ok_cnt = 0
        if proto in ("tcp", "both"):
            for p in ports:
                total += 1
                ok, resp = tcp_client_test(target_ip, p, message, timeout=5.0, no_time_wait=no_time_wait)
                log(f"[Client TCP {target_ip}:{p}] => {resp if resp else ok}")
                if ok:
                    ok_cnt += 1
        if proto in ("udp", "both"):
            for p in ports:
                total += 1
                ok, resp = udp_client_test(target_ip, p, message, timeout=5.0)
                log(f"[Client UDP {target_ip}:{p}] => {resp if resp else ok}")
                if ok:
                    ok_cnt += 1
        log(f"[Client] Done: {ok_cnt}/{total} OK.")
        return 0

    else:
        print("Unknown mode", file=sys.stderr)
        return 2


def build_arg_parser():
    p = argparse.ArgumentParser(description="Socket Test Tool — 端口优雅关闭 + NIC + Ping")
    sub = p.add_subparsers(dest="mode")

    # server
    ps = sub.add_parser("server", help="Run as server")
    ps.add_argument("--bind-ip", default="0.0.0.0", help="Bind IP")
    ps.add_argument("--ports", required=True, help="e.g. 8000,8001-8003")
    ps.add_argument("--proto", choices=["tcp", "udp", "both"], default="both")
    ps.add_argument("--message", default="test")

    # client
    pc = sub.add_parser("client", help="Run as client tester")
    pc.add_argument("--target-ip", default="127.0.0.1", help="Target IP")
    pc.add_argument("--ports", required=True, help="e.g. 8000,8001-8003")
    pc.add_argument("--proto", choices=["tcp", "udp", "both"], default="both")
    pc.add_argument("--message", default="test")
    pc.add_argument("--no-time-wait", action="store_true", help="Use TCP SO_LINGER to avoid TIME_WAIT (test only)")

    # ping
    pp = sub.add_parser("ping", help="Ping a host and print stats")
    pp.add_argument("--host", required=True, help="Host or IP to ping")
    pp.add_argument("--count", type=int, default=4, help="Number of echo requests (default 4)")
    pp.add_argument("--timeout", type=int, default=1000, help="Timeout per request in ms (default 1000)")
    pp.add_argument("--interval", type=int, default=1000, help="Interval between requests in ms (default 1000)")

    # nic
    pn = sub.add_parser("nic", help="Manage NIC (Windows first)")
    pn_sub = pn.add_subparsers(dest="nic_action")

    pn_sub.add_parser("list", help="List interfaces (Windows)")

    pn_static = pn_sub.add_parser("static", help="Set static IP")
    pn_static.add_argument("--name", required=True, help="Interface name")
    pn_static.add_argument("--ip", required=True, help="IPv4 address")
    pn_static.add_argument("--mask", required=True, help="Subnet mask (e.g. 255.255.255.0)")
    pn_static.add_argument("--gateway", default=None, help="Gateway")
    pn_static.add_argument("--dns1", default=None, help="Primary DNS")
    pn_static.add_argument("--dns2", default=None, help="Secondary DNS")

    pn_dhcp = pn_sub.add_parser("dhcp", help="Switch to DHCP")
    pn_dhcp.add_argument("--name", required=True, help="Interface name")

    p.add_argument("--nogui", action="store_true", help="Do not launch GUI; use CLI only")
    return p


def main():
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.nogui or not GUI_AVAILABLE or args.mode in ("server", "client", "nic", "ping"):
        if args.mode is None and not args.nogui:
            parser.print_help()
            return 1
        return run_cli(args)
    else:
        app = SocketToolGUI()
        app.run()
        return 0


if __name__ == "__main__":
    sys.exit(main())
