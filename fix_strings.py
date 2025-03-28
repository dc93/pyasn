#!/usr/bin/env python3
"""
Script di riparazione mirata per file PyASN specifici
Affronta i problemi esatti identificati nell'analisi precedente
"""
import os
import sys
import re

# Directory di base
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
print(f"Directory script: {SCRIPT_DIR}")

# File problematici e loro righe specifiche
PROBLEM_FILES = {
    os.path.join(SCRIPT_DIR, "interfaces", "cli.py"): [139, 141],
    os.path.join(SCRIPT_DIR, "services", "asn_lookup.py"): [221, 229],
    os.path.join(SCRIPT_DIR, "services", "ip_lookup.py"): [21, 282, 286],
    os.path.join(SCRIPT_DIR, "utils", "cache.py"): [147, 151]
}

def read_file_safely(file_path):
    """Legge un file con diverse codifiche di fallback"""
    encodings = ['utf-8', 'latin-1', 'cp1252', 'ascii']
    
    for encoding in encodings:
        try:
            with open(file_path, 'r', encoding=encoding) as f:
                lines = f.readlines()
            return lines, encoding
        except UnicodeDecodeError:
            continue
    
    print(f"ERRORE: Impossibile leggere {file_path}")
    return None, None

def write_file_safely(file_path, lines, encoding):
    """Scrive un file con la codifica specificata"""
    try:
        with open(file_path, 'w', encoding=encoding) as f:
            f.writelines(lines)
        return True
    except Exception as e:
        print(f"ERRORE: Impossibile scrivere {file_path}: {e}")
        return False

def fix_cli_file():
    """Corregge problemi in cli.py"""
    file_path = os.path.join(SCRIPT_DIR, "interfaces", "cli.py")
    print(f"\nCorrezione di {file_path}")
    
    lines, encoding = read_file_safely(file_path)
    if not lines:
        return False
    
    # Mostra le linee problematiche
    for i in range(max(0, 138), min(len(lines), 142)):
        print(f"Linea {i+1}: {repr(lines[i])}")
    
    # Correggi l'errore alla riga 139
    if len(lines) > 139:
        # Sostituzione completa della linea problematica
        lines[138] = '                print(f"IPv4 blocks ({len(result.ipv4_blocks)}):")\n'
        print(f"Linea 139 corretta: {repr(lines[138])}")
    
    # Correggi l'errore alla riga 141
    if len(lines) > 141:
        # Cerca se la riga 141 contiene una stringa non terminata
        if '"' in lines[140] and lines[140].count('"') % 2 == 1:
            lines[140] = lines[140].rstrip() + '"\n'
            print(f"Linea 141 corretta: {repr(lines[140])}")
    
    # Scrivi il file corretto
    return write_file_safely(file_path, lines, encoding)

def fix_asn_lookup_file():
    """Corregge problemi in asn_lookup.py"""
    file_path = os.path.join(SCRIPT_DIR, "services", "asn_lookup.py")
    print(f"\nCorrezione di {file_path}")
    
    lines, encoding = read_file_safely(file_path)
    if not lines:
        return False
    
    # Mostra le linee problematiche
    for i in range(max(0, 220), min(len(lines), 222)):
        print(f"Linea {i+1}: {repr(lines[i])}")
    
    for i in range(max(0, 228), min(len(lines), 230)):
        print(f"Linea {i+1}: {repr(lines[i])}")
    
    # Correggi l'errore alla riga 221
    if len(lines) > 221:
        # Cerca una stringa non terminata
        if '"' in lines[220] and lines[220].count('"') % 2 == 1:
            lines[220] = lines[220].rstrip() + '"\n'
            print(f"Linea 221 corretta: {repr(lines[220])}")
    
    # Correggi l'errore alla riga 229
    if len(lines) > 229:
        # Cerca una stringa non terminata
        if '"' in lines[228] and lines[228].count('"') % 2 == 1:
            lines[228] = lines[228].rstrip() + '"\n'
            print(f"Linea 229 corretta: {repr(lines[228])}")
    
    # Scrivi il file corretto
    return write_file_safely(file_path, lines, encoding)

def fix_ip_lookup_file():
    """Corregge problemi in ip_lookup.py"""
    file_path = os.path.join(SCRIPT_DIR, "services", "ip_lookup.py")
    print(f"\nCorrezione di {file_path}")
    
    lines, encoding = read_file_safely(file_path)
    if not lines:
        return False
    
    # Mostra le linee problematiche
    for i in range(max(0, 20), min(len(lines), 22)):
        print(f"Linea {i+1}: {repr(lines[i])}")
    
    for i in range(max(0, 281), min(len(lines), 287)):
        print(f"Linea {i+1}: {repr(lines[i])}")
    
    # Correggi l'errore alla riga 21 (verifica la sintassi)
    if len(lines) > 21:
        # Se contiene una tripla importazione su una riga che può causare problemi
        if "from typing import Dict, List, Optional, Tuple, Callable" in lines[20]:
            # Dividi in importazioni multiple
            lines[20] = "from typing import Dict, List, Optional, Tuple\n"
            # Aggiungi la riga per Callable
            lines.insert(21, "from typing import Callable\n")
            print(f"Linea 21 corretta: {repr(lines[20])}")
            print(f"Nuova linea 22: {repr(lines[21])}")
    
    # Correggi l'errore dalla riga 282-286 (blocco for indentato mancante)
    if len(lines) > 286:
        # Controlla se c'è un ciclo for seguito da line break senza indentazione
        if "for" in lines[281] and lines[281].strip().endswith(":"):
            # Verifica se manca l'indentazione nelle righe successive
            if not lines[282].startswith((" ", "\t")):
                # Aggiungi indentazione a quattro spazi
                indent = "    "
                lines[282] = indent + lines[282]
                print(f"Linea 283 corretta con indentazione: {repr(lines[282])}")
    
    # Scrivi il file corretto
    return write_file_safely(file_path, lines, encoding)

def fix_cache_file():
    """Corregge problemi in cache.py"""
    file_path = os.path.join(SCRIPT_DIR, "utils", "cache.py")
    print(f"\nCorrezione di {file_path}")
    
    lines, encoding = read_file_safely(file_path)
    if not lines:
        return False
    
    # Mostra le linee problematiche
    for i in range(max(0, 146), min(len(lines), 148)):
        print(f"Linea {i+1}: {repr(lines[i])}")
    
    for i in range(max(0, 150), min(len(lines), 152)):
        print(f"Linea {i+1}: {repr(lines[i])}")
    
    # Correggi l'errore alla riga 147
    if len(lines) > 147:
        # Cerca una stringa non terminata
        if '"' in lines[146] and lines[146].count('"') % 2 == 1:
            lines[146] = lines[146].rstrip() + '"\n'
            print(f"Linea 147 corretta: {repr(lines[146])}")
    
    # Correggi l'errore alla riga 151
    if len(lines) > 151:
        # Cerca una stringa non terminata
        if '"' in lines[150] and lines[150].count('"') % 2 == 1:
            lines[150] = lines[150].rstrip() + '"\n'
            print(f"Linea 151 corretta: {repr(lines[150])}")
    
    # Scrivi il file corretto
    return write_file_safely(file_path, lines, encoding)

def fix_files_interactive():
    """Corregge ogni file problematico con conferma interattiva"""
    fixed_files = []
    
    # Offri la possibilità di correggere ogni file
    if input("\nCcorreggere cli.py? (s/n): ").lower().startswith('s'):
        if fix_cli_file():
            fixed_files.append("cli.py")
    
    if input("\nCorreggere asn_lookup.py? (s/n): ").lower().startswith('s'):
        if fix_asn_lookup_file():
            fixed_files.append("asn_lookup.py")
    
    if input("\nCorreggere ip_lookup.py? (s/n): ").lower().startswith('s'):
        if fix_ip_lookup_file():
            fixed_files.append("ip_lookup.py")
    
    if input("\nCorreggere cache.py? (s/n): ").lower().startswith('s'):
        if fix_cache_file():
            fixed_files.append("cache.py")
    
    # Rapporto finale
    print("\nRapporto finale:")
    print(f"File corretti: {len(fixed_files)}")
    
    if fixed_files:
        print("\nFile corretti:")
        for file in fixed_files:
            print(f" - {file}")
    
    print("\nCorrezione completata. Ora puoi eseguire run_pyasn.py")

def fix_all_files_automatically():
    """Corregge tutti i file problematici automaticamente"""
    fixed_files = []
    
    if fix_cli_file():
        fixed_files.append("cli.py")
    
    if fix_asn_lookup_file():
        fixed_files.append("asn_lookup.py")
    
    if fix_ip_lookup_file():
        fixed_files.append("ip_lookup.py")
    
    if fix_cache_file():
        fixed_files.append("cache.py")
    
    # Rapporto finale
    print("\nRapporto finale:")
    print(f"File corretti: {len(fixed_files)}")
    
    if fixed_files:
        print("\nFile corretti:")
        for file in fixed_files:
            print(f" - {file}")
    
    print("\nCorrezione completata. Ora puoi eseguire run_pyasn.py")

def main():
    """Funzione principale"""
    print("=== Script di riparazione mirata per PyASN ===")
    
    mode = input("Modalità: (1) Interattiva (2) Automatica: ").strip()
    
    if mode == "1":
        fix_files_interactive()
    else:
        fix_all_files_automatically()

if __name__ == "__main__":
    main()