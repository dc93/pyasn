import os
import glob

def find_file(filename, start_path='.'):
    """Trova un file ricorsivamente a partire dalla directory specificata"""
    print(f"Cercando {filename}...")
    
    for root, dirs, files in os.walk(start_path):
        if filename in files:
            full_path = os.path.join(root, filename)
            print(f"File trovato: {full_path}")
            return full_path
    
    print(f"File {filename} non trovato.")
    return None

def apply_fix(file_path):
    """Applica il fix al file specificato"""
    print(f"Applicando il fix a {file_path}...")
    
    with open(file_path, 'r') as file:
        content = file.read()

    # Verifica se il codice vecchio è presente
    old_code = """    if self.session is None:
        self.session = aiohttp.ClientSession(
            headers={"User-Agent": self.config.user_agent}
        )"""

    if old_code not in content:
        print("Il codice da modificare non è stato trovato nel file. Verificare il contenuto.")
        return False

    new_code = """    # Initialize session if needed, with lock to prevent race conditions
    if self.session is None:
        # Use a class attribute lock if this is called concurrently
        if not hasattr(self.__class__, '_session_init_lock'):
            self.__class__._session_init_lock = asyncio.Lock()
        
        async with self.__class__._session_init_lock:
            # Check again in case another task initialized it while we were waiting
            if self.session is None:
                self.session = aiohttp.ClientSession(
                    headers={"User-Agent": self.config.user_agent}
                )"""

    # Verifica se è necessario aggiungere l'import di asyncio
    if "import asyncio" not in content and "from asyncio import" not in content:
        # Cerca la posizione dopo gli import esistenti
        import_lines = content.split("\n")
        import_position = 0
        
        for i, line in enumerate(import_lines):
            if line.startswith("import ") or line.startswith("from "):
                import_position = i + 1
        
        import_lines.insert(import_position, "import asyncio")
        content = "\n".join(import_lines)
        print("Aggiunto import per asyncio")

    updated_content = content.replace(old_code, new_code)

    with open(file_path, 'w') as file:
        file.write(updated_content)

    print("Fix applicato con successo!")
    return True

# Cerca il file nella directory corrente e sottodirectory
file_path = find_file("network_client.py")

if file_path:
    # Applica il fix
    apply_fix(file_path)
else:
    # Se il file non viene trovato, chiedi all'utente il percorso
    print("\nSpecificare il percorso completo al file network_client.py:")
    user_path = input("> ").strip()
    
    if os.path.exists(user_path) and os.path.isfile(user_path):
        apply_fix(user_path)
    else:
        print(f"Il file {user_path} non esiste o non è un file valido.")