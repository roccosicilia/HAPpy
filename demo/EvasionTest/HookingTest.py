import ctypes

# carica ntdll
ntdll = ctypes.WinDLL("ntdll.dll")

# ottieni indirizzo funzione
NtCreateFile = ntdll.NtCreateFile
addr = ctypes.cast(NtCreateFile, ctypes.c_void_p).value

print(f"NtCreateFile address: 0x{addr:x}\n")

# numero di byte da leggere
length = 20

# crea array di byte dalla memoria
buffer = (ctypes.c_ubyte * length).from_address(addr)

# stampa hex
print("First bytes:")
for b in buffer:
    print(f"{b:02X}", end=" ")
print()

# converti in lista
bytes_list = list(buffer)

# controllo hook
if bytes_list[0] in (0xE9, 0xFF):
    print("\nPossible INLINE HOOK detected")
elif bytes_list[0] == 0x4C and bytes_list[1] == 0x8B and bytes_list[2] == 0xD1:
    print("\nLikely original syscall stub")
else:
    print("\nUnknown stub format")