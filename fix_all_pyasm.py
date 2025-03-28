#!/usr/bin/env python3
"""
Script di riparazione completo per PyASN
Risolve tutti i problemi di sintassi relativi a stringhe non terminate
e altri errori comuni di codice
"""
import os
import sys
import re
import ast
import time

# Impostazioni globali
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
FIXED_FILES = []
ERRORS_FOUND = []
PYTHON_EXTENSIONS = ['.py']

def log(message):
    """Registra un messaggio con timestamp"""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}")

def is_python_file(file_path):
    """Verifica se il file è un file Python valido"""
    _, ext = os.path.splitext(file_path)
    return ext.lower() in PYTHON_EXTENSIONS

def read_file_with_fallback_encodings(file_path):
    """Legge un file con diversi encoding di fallback"""
    encodings = ['utf-8', 'latin-1', 'cp1252', 'ascii']
    
    for encoding in encodings:
        try:
            with open(file_path, 'r', encoding=encoding) as f:
                content = f.read()
            return content, encoding
        except UnicodeDecodeError:
            continue
    
    log(f"ERRORE: Impossibile leggere {file_path} con gli encoding disponibili")
    return None, None

def verify_syntax(file_content, file_path):
    """Verifica la sintassi Python utilizzando il modulo ast"""
    try:
        ast.parse(file_content)
        return True, None
    except SyntaxError as e:
        return False, (e.lineno, e.offset, str(e))

def fix_unterminated_strings(content):
    """Corregge stringhe non terminate nel codice"""
    lines = content.split('\n')
    fixed = False
    
    for i in range(len(lines)):
        line = lines[i]
        
        # Controllo stringhe singole aperte ma non chiuse
        single_quotes = line.count("'")
        if single_quotes % 2 == 1 and "'''" not in line:
            lines[i] = line + "'"
            fixed = True
        
        # Controllo stringhe doppie aperte ma non chiuse
        double_quotes = line.count('"')
        if double_quotes % 2 == 1 and '"""' not in line:
            lines[i] = line + '"'
            fixed = True
        
        # Controllo f-string non terminate
        f_string_matches = re.findall(r'f["\']', line)
        for match in f_string_matches:
            quote = match[1]
            if line.count(quote, line.find(match)) % 2 == 1:
                lines[i] = line + quote
                fixed = True
    
    if fixed:
        return '\n'.join(lines)
    return content

def fix_missing_colons(content):
    """Corregge le mancanze di ':' alla fine dei blocchi di codice"""
    lines = content.split('\n')
    fixed = False
    
    for i in range(len(lines)):
        line = lines[i].rstrip()
        
        # Controlla se la riga dovrebbe avere un ':'
        if any(keyword in line for keyword in 
              ['if ', 'elif ', 'else', 'for ', 'while ', 'def ', 'class ', 'try', 'except ', 'finally']):
            # Se non termina con ':' e non è una continuazione di linea
            if not line.endswith(':') and not line.endswith('\\'):
                # Se è una riga completa che dovrebbe terminare con ':'
                # (non dovrebbe esserci un'operazione in sospeso)
                parentheses_balance = line.count('(') - line.count(')')
                brackets_balance = line.count('[') - line.count(']')
                braces_balance = line.count('{') - line.count('}')
                
                if parentheses_balance == 0 and brackets_balance == 0 and braces_balance == 0:
                    lines[i] = line + ':'
                    fixed = True
    
    if fixed:
        return '\n'.join(lines)
    return content

def fix_try_except_blocks(content):
    """Corregge blocchi try senza except o finally"""
    lines = content.split('\n')
    fixed = False
    i = 0
    
    while i < len(lines):
        line = lines[i].strip()
        
        if line.startswith('try:'):
            # Controlla se ci sono except o finally nei prossimi 10 blocchi
            has_handler = False
            lookahead = min(10, len(lines) - i - 1)
            
            for j in range(1, lookahead + 1):
                next_line = lines[i + j].strip()
                if next_line.startswith(('except', 'finally:')):
                    has_handler = True
                    break
            
            if not has_handler:
                # Aggiungi un gestore except dopo il blocco try
                indentation = len(lines[i]) - len(lines[i].lstrip())
                indent = ' ' * indentation
                
                # Inserisci except Exception dopo il blocco try
                lines.insert(i + 1, f"{indent}except Exception as e:")
                lines.insert(i + 2, f"{indent}    print(f\"Errore: {{e}}\")")
                fixed = True
                i += 2  # Aggiustiamo l'indice per le righe inserite
        
        i += 1
    
    if fixed:
        return '\n'.join(lines)
    return content

def fix_file_syntax(file_path):
    """Corregge errori di sintassi in un file Python"""
    log(f"Analisi del file: {file_path}")
    
    content, encoding = read_file_with_fallback_encodings(file_path)
    if content is None:
        ERRORS_FOUND.append((file_path, "Impossibile leggere il file"))
        return False
    
    # Verifica la sintassi iniziale
    is_valid, error = verify_syntax(content, file_path)
    if is_valid:
        log(f"File sintatticamente corretto: {file_path}")
        return False
    
    # Registra l'errore originale
    if error:
        line_num, offset, error_msg = error
        log(f"Errore di sintassi trovato: Linea {line_num}, Pos {offset}: {error_msg}")
    
    # Applica le correzioni
    original_content = content
    
    # Prova diverse correzioni fino a quando la sintassi è valida
    content = fix_unterminated_strings(content)
    is_valid, _ = verify_syntax(content, file_path)
    
    if not is_valid:
        content = fix_missing_colons(content)
        is_valid, _ = verify_syntax(content, file_path)
    
    if not is_valid:
        content = fix_try_except_blocks(content)
        is_valid, _ = verify_syntax(content, file_path)
    
    # Se abbiamo modificato il contenuto, scrivi il file
    if content != original_content:
        try:
            with open(file_path, 'w', encoding=encoding) as f:
                f.write(content)
            
            # Verifica finale
            final_valid, final_error = verify_syntax(content, file_path)
            if final_valid:
                log(f"File corretto con successo: {file_path}")
                FIXED_FILES.append(file_path)
                return True
            else:
                line_num, offset, error_msg = final_error
                log(f"Impossibile correggere completamente: Ancora errore a Linea {line_num}, Pos {offset}: {error_msg}")
                ERRORS_FOUND.append((file_path, f"Errore residuo: {error_msg} a linea {line_num}"))
        except Exception as e:
            log(f"Errore durante la scrittura del file {file_path}: {e}")
            ERRORS_FOUND.append((file_path, f"Errore di scrittura: {e}"))
    
    return False

def scan_directory(directory):
    """Scansiona una directory per i file Python e li corregge"""
    log(f"Scansione directory: {directory}")
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            if is_python_file(file):
                file_path = os.path.join(root, file)
                fix_file_syntax(file_path)

def main():
    """Funzione principale"""
    log("Iniziando la correzione completa di PyASN")
    
    # Directories da scansionare
    directories = [
        os.path.join(SCRIPT_DIR, "core"),
        os.path.join(SCRIPT_DIR, "interfaces"),
        os.path.join(SCRIPT_DIR, "services"),
        os.path.join(SCRIPT_DIR, "utils")
    ]
    
    # Scansiona tutte le directory
    for directory in directories:
        if os.path.exists(directory):
            scan_directory(directory)
        else:
            log(f"Directory non trovata: {directory}")
    
    # Rapporto finale
    log(f"\nRapporto finale:")
    log(f"File corretti: {len(FIXED_FILES)}")
    
    if FIXED_FILES:
        log("\nFile corretti:")
        for file in FIXED_FILES:
            log(f" - {os.path.relpath(file, SCRIPT_DIR)}")
    
    if ERRORS_FOUND:
        log("\nErrori residui:")
        for file_path, error in ERRORS_FOUND:
            log(f" - {os.path.relpath(file_path, SCRIPT_DIR)}: {error}")
    
    log("\nCorrezione completata. Ora puoi eseguire run_pyasn.py")

if __name__ == "__main__":
    main()