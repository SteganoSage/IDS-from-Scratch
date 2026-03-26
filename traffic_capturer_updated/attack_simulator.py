"""
attack_simulator.py
====================
WSL2-compatible attack traffic generator for FusionIDS testing.
Generates flows that MATCH the CIC-IDS2018 training data patterns.

Key design principle — each attack reuses the same connection (same src_port)
to build ONE large flow with many packets, matching how CIC-IDS captured them:

  CIC-IDS BruteForce:   1 persistent connection, hundreds of PSH/ACK exchanges
  CIC-IDS DoS:          2-3 connections, flood of packets on same socket
  CIC-IDS PortScan:     1 flow per port (already correct)
  CIC-IDS Bot:          long idle flow with periodic beaconing bursts
  CIC-IDS Infiltration: slow data exfiltration over one connection

Usage:
    # Terminal 1 — IDS
    sudo ./ids eth0 --timeout 30 --expiry 5000

    # Terminal 2 — run attacks (starts its own echo listener internally)
    python3 attack_simulator.py --target 127.0.0.1 --attack all
    python3 attack_simulator.py --target 127.0.0.1 --attack brute_force
    python3 attack_simulator.py --target 127.0.0.1 --attack dos
    python3 attack_simulator.py --target 127.0.0.1 --attack port_scan
    python3 attack_simulator.py --target 127.0.0.1 --attack bot
    python3 attack_simulator.py --target 127.0.0.1 --attack infiltration
"""

import argparse
import socket
import threading
import time
import random
from datetime import datetime

DEFAULT_TARGET = "127.0.0.1"
LISTEN_PORT    = 8080

def log(tag, msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] [{tag:12s}] {msg}")


# ── Echo listener — gives bwd packets to all flows ────────────────────────────
class EchoListener:
    def __init__(self, port):
        self.port  = port
        self._stop = threading.Event()

    def start(self):
        threading.Thread(target=self._run, daemon=True).start()
        time.sleep(0.3)
        log("LISTENER", f"Echo server ready on :{self.port}")

    def stop(self): self._stop.set()

    def _run(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", self.port))
        srv.listen(512)
        srv.settimeout(1.0)
        while not self._stop.is_set():
            try:
                conn, _ = srv.accept()
                threading.Thread(target=self._handle, args=(conn,), daemon=True).start()
            except socket.timeout:
                continue
        srv.close()

    def _handle(self, conn):
        conn.settimeout(5.0)
        try:
            while True:
                data = conn.recv(4096)
                if not data: break
                conn.sendall(
                    b"HTTP/1.1 401 Unauthorized\r\n"
                    b"Content-Length: 13\r\n"
                    b"Connection: keep-alive\r\n\r\n"
                    b"Unauthorized\n"
                )
        except Exception:
            pass
        finally:
            conn.close()


# ── Attack 1: BruteForce ──────────────────────────────────────────────────────
# 3 persistent connections × 200 PSH/ACK exchanges each
# = 3 large flows with high PSH count, bidirectional traffic
def brute_force(target, port, threads=3, attempts=200):
    log("BRUTE_FORCE", f"{threads} persistent connections × {attempts} login attempts each")
    users = ["admin","root","user","administrator","guest","test"]
    pwds  = ["password","123456","admin","letmein","qwerty","12345678"]

    def worker(tid):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10.0)
            s.connect((target, port))
            log("BRUTE_FORCE", f"  Thread {tid}: connected")
            for i in range(attempts):
                body = f"username={random.choice(users)}&password={random.choice(pwds)}&n={i}"
                req  = (f"POST /login HTTP/1.1\r\nHost: {target}\r\n"
                        f"Content-Type: application/x-www-form-urlencoded\r\n"
                        f"Content-Length: {len(body)}\r\nConnection: keep-alive\r\n\r\n{body}")
                s.sendall(req.encode())
                try: s.recv(256)
                except: pass
                time.sleep(0.01)
            s.close()
            log("BRUTE_FORCE", f"  Thread {tid}: done")
        except Exception as e:
            log("BRUTE_FORCE", f"  Thread {tid}: {e}")

    ts = [threading.Thread(target=worker, args=(i,)) for i in range(threads)]
    for t in ts: t.start()
    for t in ts: t.join()
    log("BRUTE_FORCE", f"Done — {threads} flows, ~{attempts} PSH exchanges each")


# ── Attack 2: DoS ─────────────────────────────────────────────────────────────
# 3 persistent connections flood same socket for 20s
# = 3 massive flows with thousands of packets
def dos_flood(target, port, connections=3, duration=20):
    log("DOS_FLOOD", f"{connections} persistent connections flooding for {duration}s")
    stop  = threading.Event()
    counts = [0] * connections

    def worker(idx):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5.0)
            s.connect((target, port))
            log("DOS_FLOOD", f"  Conn {idx}: flooding...")
            while not stop.is_set():
                req = f"GET /?r={random.randint(0,99999)} HTTP/1.1\r\nHost: {target}\r\n\r\n"
                s.sendall(req.encode())
                try: s.recv(256)
                except: pass
                counts[idx] += 1
            s.close()
            log("DOS_FLOOD", f"  Conn {idx}: {counts[idx]} requests")
        except Exception as e:
            log("DOS_FLOOD", f"  Conn {idx}: {e}")

    ts = [threading.Thread(target=worker, args=(i,)) for i in range(connections)]
    for t in ts: t.start()
    time.sleep(duration)
    stop.set()
    for t in ts: t.join(timeout=3)
    log("DOS_FLOOD", f"Done — {sum(counts)} total reqs across {connections} flows")


# ── Attack 3: Port Scan ───────────────────────────────────────────────────────
# 1 connection attempt per port — already matches CIC-IDS pattern
def port_scan(target, start=1, end=1024, threads=100):
    log("PORT_SCAN", f"Scanning ports {start}-{end} ({end-start+1} flows)")
    ports = list(range(start, end + 1))
    open_ports = []
    lock = threading.Lock()
    idx  = [0]

    def worker():
        while True:
            with lock:
                if idx[0] >= len(ports): return
                port = ports[idx[0]]; idx[0] += 1
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.15)
                s.connect((target, port))
                with lock: open_ports.append(port)
                s.close()
            except: pass

    ts = [threading.Thread(target=worker) for _ in range(threads)]
    for t in ts: t.start()
    for t in ts: t.join()
    log("PORT_SCAN", f"Done — open: {open_ports or 'none'}")


# ── Attack 4: Bot Beaconing ───────────────────────────────────────────────────
# 1 long-lived connection with periodic idle + burst gaps
# = 1 flow with high Idle Mean, periodic Active bursts
def bot_beacon(target, port, beacons=15, interval=3.0):
    log("BOT", f"1 connection, {beacons} beacons every {interval}s")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10.0)
        s.connect((target, port))
        log("BOT", "Connected — beaconing...")
        for i in range(beacons):
            msg = f"BEACON id=bot-001 seq={i} ts={int(time.time())}\r\n"
            s.sendall(msg.encode())
            try: s.recv(256)
            except: pass
            log("BOT", f"  Beacon {i+1}/{beacons}")
            time.sleep(interval)
        s.close()
        log("BOT", f"Done — 1 flow, {beacons} beacons, ~{beacons*interval:.0f}s duration")
    except Exception as e:
        log("BOT", f"Error: {e}")


# ── Attack 5: Infiltration ────────────────────────────────────────────────────
# 1 connection with large sustained data transfer
# = high TotLen Fwd Pkts, many PSH flags, sustained duration
def infiltration(target, port, chunks=100, chunk_size=1400):
    log("INFILTRATION", f"Exfiltrating {chunks*chunk_size//1024}KB over 1 connection")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10.0)
        s.connect((target, port))
        log("INFILTRATION", "Connected — transferring...")
        for i in range(chunks):
            header = (f"POST /upload HTTP/1.1\r\nHost: {target}\r\n"
                      f"Content-Length: {chunk_size}\r\n\r\n").encode()
            data = header + bytes([random.randint(32,126) for _ in range(chunk_size)])
            s.sendall(data)
            try: s.recv(256)
            except: pass
            time.sleep(0.05)
        s.close()
        log("INFILTRATION", f"Done — {chunks*chunk_size//1024}KB in 1 flow")
    except Exception as e:
        log("INFILTRATION", f"Error: {e}")


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--port",   type=int, default=LISTEN_PORT)
    parser.add_argument("--attack", default="all",
                        choices=["all","brute_force","dos","port_scan",
                                 "bot","infiltration"])
    args = parser.parse_args()

    print(f"""
╔══════════════════════════════════════════════════════╗
║   FusionIDS Attack Simulator v2 (CIC-IDS2018 style) ║
╠══════════════════════════════════════════════════════╣
║  Target : {args.target}:{args.port:<43}║
║  Attack : {args.attack:<46}║
╚══════════════════════════════════════════════════════╝
""")

    listener = EchoListener(args.port)
    listener.start()
    time.sleep(1)

    if args.attack in ("brute_force", "all"):
        print("\n── BruteForce ─────────────────────────────────────────")
        brute_force(args.target, args.port)
        time.sleep(5)

    if args.attack in ("dos", "all"):
        print("\n── DoS Flood ──────────────────────────────────────────")
        dos_flood(args.target, args.port)
        time.sleep(5)

    if args.attack in ("port_scan", "all"):
        print("\n── Port Scan ──────────────────────────────────────────")
        port_scan(args.target, end=500)
        time.sleep(5)

    if args.attack in ("bot", "all"):
        print("\n── Bot Beaconing ──────────────────────────────────────")
        bot_beacon(args.target, args.port)
        time.sleep(5)

    if args.attack in ("infiltration", "all"):
        print("\n── Infiltration ───────────────────────────────────────")
        infiltration(args.target, args.port)
        time.sleep(3)

    listener.stop()
    print("""
✅  Done. Expected IDS flow signatures:
   BruteForce  : proto=6, high PSH Cnt, bidirectional, ~2s duration
   DoS         : proto=6, thousands of pkts, high byte rate, 3 flows
   PortScan    : proto=6, 1 pkt each, ~500 short flows
   Bot         : proto=6, long duration, high Idle Mean
   Infiltration: proto=6, high TotLen Fwd, many PSH
""")

if __name__ == "__main__":
    main()