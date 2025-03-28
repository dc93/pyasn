#!/usr/bin/env python3
"""
Script per correggere automaticamente gli errori di sintassi nei file di PyASN
"""
import os
import sys
import re

# Ottieni la directory corrente
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
print(f"Directory script: {SCRIPT_DIR}")

def check_and_fix_file(file_path, encoding='utf-8'):
    """Verifica e corregge errori di sintassi comuni in un file Python"""
    try:
        with open(file_path, 'r', encoding=encoding) as f:
            lines = f.readlines()
        
        original_lines = lines.copy()
        fixed = False
        
        # Verifica se ci sono correzioni da applicare
        for i in range(len(lines)):
            line_num = i + 1
            
            # Correggi f-string non terminate
            if 'f"' in lines[i] and '"' not in lines[i].split('f"', 1)[1]:
                print(f"Riga {line_num}: Trovato f-string non terminato")
                lines[i] = lines[i].rstrip() + '"\n'
                fixed = True
            
            # Correggi blocchi try/except mal formati
            if line_num >= 490 and file_path.endswith("cli.py"):
                if i >= 489 and i <= 491:
                    print(f"Riga {line_num}: {lines[i].strip()}")
                
                # Se c'è 'try:' senza un matching 'except' o 'finally'
                if 'try:' in lines[i] and i+1 < len(lines):
                    next_few_lines = ''.join(lines[i+1:i+6])
                    if 'except' not in next_few_lines and 'finally' not in next_few_lines:
                        print(f"Riga {line_num}: Blocco try senza except/finally")
                        # Aggiungi una clausola except semplice dopo la riga try
                        lines.insert(i+1, "                except Exception as e:\n")
                        lines.insert(i+2, "                    print(f\"Errore: {e}\")\n")
                        fixed = True
            
            # Verifica mancanza di ':' alla fine di una riga in ip_lookup.py
            if file_path.endswith("ip_lookup.py") and line_num == 282:
                print(f"Riga {line_num}: {lines[i].strip()}")
                
                # Se la riga contiene 'for' o 'if' o 'while' o 'def' o 'class' o 'else' ma non termina con ':'
                if any(keyword in lines[i] for keyword in ['for ', 'if ', 'while ', 'def ', 'class ', 'else']) and \
                   not lines[i].strip().endswith(':'):
                    print(f"Riga {line_num}: Manca ':' alla fine della riga")
                    lines[i] = lines[i].rstrip() + ':\n'
                    fixed = True
        
        # Se ci sono correzioni, scrivi il file aggiornato
        if fixed:
            print(f"Applicazione delle correzioni a {file_path}")
            with open(file_path, 'w', encoding=encoding) as f:
                f.writelines(lines)
            return True
        else:
            print(f"Nessuna correzione necessaria per {file_path}")
            return False
    
    except Exception as e:
        print(f"Errore durante la correzione di {file_path}: {e}")
        return False

# File da controllare e correggere
files_to_check = [
    os.path.join(SCRIPT_DIR, "interfaces", "cli.py"),
    os.path.join(SCRIPT_DIR, "services", "ip_lookup.py"),
    os.path.join(SCRIPT_DIR, "interfaces", "web_server.py")
]

# Controlla e correggi ogni file
for file_path in files_to_check:
    if os.path.exists(file_path):
        print(f"\nVerifica e correzione di {file_path}...")
        check_and_fix_file(file_path)
    else:
        print(f"\nFile non trovato: {file_path}")

print("\nCorrezioni completate. Ora puoi eseguire run_pyasn.py")