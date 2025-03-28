#!/usr/bin/env python3
"""
PyASN Launcher Script con correzioni automatiche di problemi di sintassi
"""
import os
import sys
import types
import importlib.util
import argparse
from pathlib import Path
import re

# Ottieni la directory dello script
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
print(f"Directory script: {SCRIPT_DIR}")

# Definizione della versione
__version__ = "1.0.0"

def fix_cli_syntax():
    """Corregge l'errore di sintassi nell'f-string in cli.py"""
    cli_path = os.path.join(SCRIPT_DIR, "interfaces", "cli.py")
    
    if not os.path.exists(cli_path):
        print(f"ERRORE: File cli.py non trovato in {cli_path}")
        return False
    
    try:
        with open(cli_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Cerca di identificare e correggere l'f-string non terminato alla linea 486
        lines = content.split('\n')
        if len(lines) >= 486:
            line_485 = lines[484] if len(lines) > 484 else ""
            line_486 = lines[485] if len(lines) > 485 else ""
            line_487 = lines[486] if len(lines) > 486 else ""
            
            print(f"Riga 485: {line_485}")
            print(f"Riga 486: {line_486}")
            print(f"Riga 487: {line_487}")
            
            # Verifica se la linea 486 contiene un f-string non terminato
            if line_486.startswith('                print(f"IPv4'):
                # La riga conteneva un f-string non terminato
                # Risolviamo concatenando con la linea successiva se esiste
                if line_487:
                    fixed_line = line_486 + ' ' + line_487
                else:
                    fixed_line = line_486 + '")'  # Chiudi l'f-string
                
                lines[485] = fixed_line
                if line_487:
                    lines.pop(486)  # Rimuovi la linea 487 poiché l'abbiamo unita alla 486
                
                # Scrivi il file corretto
                with open(cli_path, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(lines))
                
                print("Correzione applicata all'f-string non terminato in cli.py")
                return True
    except Exception as e:
        print(f"Errore durante il tentativo di correggere cli.py: {e}")
    
    return False

def load_module_from_file(module_name, file_path):
    """Carica un modulo Python direttamente da un file"""
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    if spec is None:
        print(f"Impossibile caricare il modulo {module_name} da {file_path}")
        return None
        
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
        return module
    except Exception as e:
        print(f"Errore durante il caricamento di {module_name}: {e}")
        return None

# Tentativo di correggere il problema di sintassi in cli.py
print("Verifica e correzione di problemi di sintassi...")
fix_cli_syntax()

# Crea moduli segnaposto nelle posizioni corrette
pyasn = types.ModuleType("pyasn")
pyasn.__path__ = [SCRIPT_DIR]
pyasn.__version__ = __version__
sys.modules["pyasn"] = pyasn

pyasn_core = types.ModuleType("pyasn.core")
pyasn_core.__path__ = [os.path.join(SCRIPT_DIR, "core")]
sys.modules["pyasn.core"] = pyasn_core

pyasn_interfaces = types.ModuleType("pyasn.interfaces")
pyasn_interfaces.__path__ = [os.path.join(SCRIPT_DIR, "interfaces")]
sys.modules["pyasn.interfaces"] = pyasn_interfaces

pyasn_utils = types.ModuleType("pyasn.utils")
pyasn_utils.__path__ = [os.path.join(SCRIPT_DIR, "utils")]
sys.modules["pyasn.utils"] = pyasn_utils

pyasn_services = types.ModuleType("pyasn.services")
pyasn_services.__path__ = [os.path.join(SCRIPT_DIR, "services")]
sys.modules["pyasn.services"] = pyasn_services

pyasn_core_providers = types.ModuleType("pyasn.core.providers")
pyasn_core_providers.__path__ = [os.path.join(SCRIPT_DIR, "core", "providers")]
sys.modules["pyasn.core.providers"] = pyasn_core_providers

# Carica i moduli base necessari
print("Caricamento dei moduli di base...")
exceptions = load_module_from_file("pyasn.core.exceptions", os.path.join(SCRIPT_DIR, "core", "exceptions.py"))
if not exceptions:
    print("ERRORE: Impossibile caricare il modulo delle eccezioni")
    sys.exit(1)

print("Caricamento dei moduli di utilità...")
validation = load_module_from_file("pyasn.utils.validation", os.path.join(SCRIPT_DIR, "utils", "validation.py"))
network = load_module_from_file("pyasn.utils.network", os.path.join(SCRIPT_DIR, "utils", "network.py"))
cache = load_module_from_file("pyasn.utils.cache", os.path.join(SCRIPT_DIR, "utils", "cache.py"))

if not validation or not network or not cache:
    print("ERRORE: Impossibile caricare i moduli di utilità")
    sys.exit(1)

print("Caricamento del modulo di configurazione...")
config = load_module_from_file("pyasn.core.config", os.path.join(SCRIPT_DIR, "core", "config.py"))
if not config:
    print("ERRORE: Impossibile caricare il modulo di configurazione")
    sys.exit(1)

# Carica prima services/__init__.py per definire ASNService
print("Caricamento dei servizi base...")
services_init = load_module_from_file("pyasn.services", os.path.join(SCRIPT_DIR, "services", "__init__.py"))
if not services_init:
    # Se il file non esiste, creiamo un modulo in memoria con la definizione di ASNService
    print("Creazione di un modulo services con definizioni essenziali...")
    from abc import ABC, abstractmethod
    
    class ASNService(ABC):
        """Interface for ASN lookup services"""
        @abstractmethod
        def lookup_asn(self, asn):
            pass
        @abstractmethod
        def suggest_asns(self, search_term):
            pass
    
    class IPService(ABC):
        """Interface for IP lookup services"""
        @abstractmethod
        def lookup_ip(self, ip):
            pass
        @abstractmethod
        def bulk_geolocate(self, ips):
            pass
        @abstractmethod
        def country_cidr_lookup(self, country):
            pass
    
    class TraceService(ABC):
        """Interface for path tracing services"""
        @abstractmethod
        def trace_as_path(self, target):
            pass
    
    class OrganizationService(ABC):
        """Interface for organization search services"""
        @abstractmethod
        def search_by_org(self, org_name):
            pass
    
    class ShodanService(ABC):
        """Interface for Shodan scanning services"""
        @abstractmethod
        def scan(self, targets):
            pass
    
    # Aggiungi le classi al modulo
    pyasn_services.ASNService = ASNService
    pyasn_services.IPService = IPService
    pyasn_services.TraceService = TraceService
    pyasn_services.OrganizationService = OrganizationService
    pyasn_services.ShodanService = ShodanService

print("Caricamento delle interfacce...")
cli_module = load_module_from_file("pyasn.interfaces.cli", os.path.join(SCRIPT_DIR, "interfaces", "cli.py"))
web_server_module = load_module_from_file("pyasn.interfaces.web_server", os.path.join(SCRIPT_DIR, "interfaces", "web_server.py"))

if not cli_module:
    print("ERRORE: Impossibile caricare l'interfaccia CLI")
    sys.exit(1)

if not web_server_module and '--server' in sys.argv:
    print("ERRORE: Impossibile caricare l'interfaccia server web")
    sys.exit(1)

# Ora che abbiamo caricato i moduli, possiamo procedere con il codice principale
if __name__ == "__main__":
    # Crea parser degli argomenti
    parser = argparse.ArgumentParser(description="PyASN - Network Intelligence Tool")
    parser.add_argument("--debug", action="store_true", help="Abilita logging di debug")
    parser.add_argument("--config", type=str, help="Percorso al file di configurazione")
    parser.add_argument("--server", action="store_true", help="Esegui in modalità server web")
    parser.add_argument("--version", action="store_true", help="Mostra informazioni sulla versione")
    parser.add_argument("target", nargs="*", help="Target per la ricerca (ASN, IP, hostname, URL, nome organizzazione)")
    
    # Parse just the known args for initial setup
    args, remaining = parser.parse_known_args()
    
    # Mostra la versione se richiesto
    if args.version:
        print(f"PyASN versione {__version__}")
        sys.exit(0)
    
    try:
        # Configura l'oggetto Config
        config_path = Path(args.config) if args.config else None
        config_obj = config.Config(config_path, debug=args.debug)
        
        # Esegui in modalità server o CLI
        print("Avvio di PyASN...")
        
        if args.server:
            if web_server_module:
                print("Modalità server")
                server = web_server_module.WebServer(config_obj)
                sys.exit(server.run())
            else:
                print("ERRORE: Modalità server non disponibile")
                sys.exit(1)
        else:
            print("Modalità CLI")
            cli_obj = cli_module.CLI(config_obj)
            sys.exit(cli_obj.run(sys.argv[1:]))
    except Exception as e:
        print(f"ERRORE durante l'esecuzione: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)