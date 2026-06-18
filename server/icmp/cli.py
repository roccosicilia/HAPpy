#!/usr/bin/env python3
"""
HAPpy - ICMP CLI
==================
Identica alla cli.py originale ma punta di default al server ICMP locale
(http://127.0.0.1:8080 invece di :80).

Nessuna altra modifica: la CLI non sa nulla di ICMP,
parla solo HTTP con il server locale — è il server che gestisce il canale ICMP.

Utilizzo:
    python3 icmp_cli.py [http://127.0.0.1:8080]

Requisiti:
    pip install requests
"""

import argparse
import requests
import threading
import time
import sys
import os
from datetime import datetime

POLL_INTERVAL = 1.0
PROMPT        = "\033[1;32micmp-c2\033[0m \033[1;34m»\033[0m "
CLIENT_LOG    = "../logs/c2_icmp_client.log"
SERVER_LOG    = "../logs/command_output.log"
SERVER_URL    = ""

waiting_for_output = False
lock = threading.Lock()


class CommandEntry:
    def __init__(self, handler, usage, help):
        self.handler = handler
        self.usage   = usage
        self.help    = help


def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def log_write(entry_type, content):
    with open(CLIENT_LOG, "a") as f:
        f.write(f"[{timestamp()}] [{entry_type}] {content}\n")

def clear_line():
    sys.stdout.write("\r\033[K")
    sys.stdout.flush()

def print_output(text):
    clear_line()
    print(f"\033[1;33m[{timestamp()}]\033[0m {text}")
    sys.stdout.write(PROMPT)
    sys.stdout.flush()


# ── comandi locali ────────────────────────────────────────────────────────────

def cmd_help(_args):
    col_w = max(len(e.usage) for e in COMMANDS.values()) + 4
    print(f"\n \033[1mComandi locali:\033[0m")
    for name, entry in COMMANDS.items():
        pad = col_w - len(entry.usage)
        print(f"  \033[1m{entry.usage}\033[0m{' ' * pad}{entry.help}")
    print(f"\n  Qualsiasi altra cosa viene inviata come comando remoto.\n")
    return True

def cmd_exit(_args):
    log_write("SESSION", "sessione terminata")
    print("\033[1;31mUscita.\033[0m")
    return False

def cmd_server(args):
    global SERVER_URL
    if not args:
        print(f"  server attuale: \033[1;33m{SERVER_URL}\033[0m")
        return True
    SERVER_URL = args[0].rstrip("/")
    log_write("CONFIG", f"server cambiato a {SERVER_URL}")
    print(f"  server impostato a \033[1;33m{SERVER_URL}\033[0m")
    return True

def cmd_status(_args):
    try:
        resp = requests.get(f"{SERVER_URL}/status", timeout=3)
        data = resp.json()
        cmd  = data.get("pending_command", "")
        ch   = data.get("channel", "?")
        print(f"  canale  : \033[1;36m{ch}\033[0m")
        print(f"  pending : \033[1;33m{cmd if cmd else '(nessuno)'}\033[0m")
    except requests.RequestException as e:
        print(f"  \033[1;31m[errore: {e}]\033[0m")
    return True

def cmd_log(_args):
    if not os.path.exists(CLIENT_LOG):
        print("  log non ancora creato")
        return True
    with open(CLIENT_LOG) as f:
        lines = f.readlines()
    print()
    for line in lines[-20:]:
        print(f"  {line}", end="")
    print()
    return True


COMMANDS = {
    "help":   CommandEntry(cmd_help,   "help",        "mostra questo messaggio"),
    "exit":   CommandEntry(cmd_exit,   "exit",        "chiude la CLI"),
    "quit":   CommandEntry(cmd_exit,   "quit",        "alias di exit"),
    "server": CommandEntry(cmd_server, "server [url]","legge o imposta l'URL del server locale"),
    "status": CommandEntry(cmd_status, "status",      "stato del server ICMP C2"),
    "log":    CommandEntry(cmd_log,    "log",         "ultime 20 righe del log client"),
}

# ── polling thread ────────────────────────────────────────────────────────────

def poll_loop():
    global waiting_for_output
    while True:
        time.sleep(POLL_INTERVAL)
        with lock:
            if not waiting_for_output:
                continue

        try:
            # Fase 1: aspetta che il comando venga consegnato al payload
            # (/command torna vuoto appena Scapy lo invia e lo azzera)
            resp = requests.get(f"{SERVER_URL}/command", timeout=3)
            command_pending = resp.text.strip()
        except requests.RequestException as e:
            with lock:
                if waiting_for_output:
                    print_output(f"\033[1;31m[errore di rete: {e}]\033[0m")
                    waiting_for_output = False
            continue

        if command_pending:
            # Comando ancora in coda, non ancora consegnato
            continue

        # Fase 2: comando consegnato — aspetta l'output via GET /result
        try:
            resp   = requests.get(f"{SERVER_URL}/result", timeout=3)
            output = resp.text.strip()
        except requests.RequestException as e:
            print_output(f"\033[1;31m[errore lettura output: {e}]\033[0m")
            with lock:
                waiting_for_output = False
            continue

        if not output:
            # Output non ancora arrivato dal payload, riprova al prossimo tick
            continue

        # Output ricevuto: stampalo
        clear_line()
        print(f"\n\033[1;36m┌─ output ───────────────────────────────────────\033[0m")
        for line in output.splitlines():
            print(f"\033[1;36m│\033[0m {line}")
        print(f"\033[1;36m└────────────────────────────────────────────────\033[0m")
        sys.stdout.write(PROMPT)
        sys.stdout.flush()
        log_write("OUTPUT", output.replace("\n", " | "))

        with lock:
            waiting_for_output = False

# ── main ──────────────────────────────────────────────────────────────────────

def send_command(command):
    try:
        resp = requests.post(f"{SERVER_URL}/set_command", data={"command": command}, timeout=3)
        return resp.status_code == 200
    except requests.RequestException as e:
        print(f"\033[1;31m[errore: {e}]\033[0m")
        return False

def main():
    global SERVER_URL, waiting_for_output, CLIENT_LOG

    parser = argparse.ArgumentParser(description="HAPpy ICMP CLI")
    parser.add_argument(
        "server", nargs="?",
        default=os.environ.get("C2_SERVER", "http://127.0.0.1:8080"),
        help="URL del server ICMP C2 locale (default: http://127.0.0.1:8080)"
    )
    parser.add_argument("--poll", type=float, default=POLL_INTERVAL, metavar="SEC")
    parser.add_argument("--log",  default=CLIENT_LOG, metavar="FILE")
    args = parser.parse_args()

    SERVER_URL = args.server.rstrip("/")
    CLIENT_LOG = args.log

    print(f"\033[1;32m╔══════════════════════════════════════════╗\033[0m")
    print(f"\033[1;32m║   HAPpy ICMP C2 - Command Line Interface ║\033[0m")
    print(f"\033[1;32m╚══════════════════════════════════════════╝\033[0m")
    print(f"  server  : \033[1;33m{SERVER_URL}\033[0m")
    print(f"  canale  : \033[1;36mICMP covert channel\033[0m")
    print(f"  log     : \033[1;33m{CLIENT_LOG}\033[0m")
    print(f"  digita \033[1mhelp\033[0m per i comandi\n")

    log_write("SESSION", f"sessione avviata, server={SERVER_URL}")

    t = threading.Thread(target=poll_loop, daemon=True)
    t.start()

    while True:
        try:
            sys.stdout.write(PROMPT)
            sys.stdout.flush()
            line = input().strip()
        except (EOFError, KeyboardInterrupt):
            cmd_exit([])
            sys.exit(0)

        if not line:
            continue

        parts    = line.split()
        cmd_name = parts[0].lower()
        cmd_args = parts[1:]

        if cmd_name in COMMANDS:
            if not COMMANDS[cmd_name].handler(cmd_args):
                sys.exit(0)
            continue

        with lock:
            if waiting_for_output:
                print("  \033[1;31m[attendere l'output del comando precedente]\033[0m")
                continue

        if send_command(line):
            print(f"  \033[1;33m[comando inviato via ICMP, in attesa di output...]\033[0m")
            log_write("COMMAND", line)
            with lock:
                waiting_for_output = True
        else:
            print(f"  \033[1;31m[errore nell'invio del comando]\033[0m")


if __name__ == "__main__":
    main()
    