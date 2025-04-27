# AutoPyrewall 2025

import subprocess
import sys
import pathlib as pt
import time as tm

import utility

        
            
class Firewall:
    
    NETSH_ADDRULE_CMD = ["netsh", "advfirewall", "firewall", "add", "rule"]
    NETSH_LISTRULE_CMD = ["netsh", "advfirewall", "firewall", "show rule", "name=all"]
    
    def __init__(self):
        pass
          
    
    @staticmethod
    def block_traffic(path: str, ingoing: bool = True, outgoing: bool = True):
        """
        Blocca tutto il traffico di rete in entrata e in uscita per i file .exe
        all'interno della cartella specificata.  Crea regole del firewall di Windows.
        
        Args:
            folder_path (str): Il percorso della cartella contenente i file .exe da bloccare.
        """
    
        path = pt.Path(path)
        try:
            # Verifica che il percorso della cartella esista
            if not path.is_dir():
                print(f"Errore: La cartella specificata '{folder_path}' non esiste.")
                sys.exit(1)
                
            exe_filelist = [file for file in path.iterdir() if file.suffix == ".exe"]
            # Scorre tutti i file nella cartella
            for file in exe_filelist:
                
                time_now = int(tm.time())
                time_iso = tm.ctime(time_now)
                
                ADD_RULE_CMD = ["netsh", "advfirewall", "firewall", "add", "rule"]
                SETTINGS = ["enable=yes", "profile=any"]
                # Blocca il traffico in entrata per il file .exe
                subprocess.run(
                    [*ADD_RULE_CMD, "dir=in", "action=block",
                     f'name=APW-{time_now}-BKI-{file.stem}',  #suffisso _In per la regola in entrata
                     f'program={file.absolute()}',
                     f"description=Autofirewall generated rule at {time_iso} by Python process.",
                     *SETTINGS] ,
                    check=True
                )
        
                # Blocca il traffico in uscita per il file .exe
                subprocess.run(
                    [*ADD_RULE_CMD, "dir=out", "action=block",
                     f'name=APW-{time_now}-BKO-{file.stem}', #suffisso _Out per la regola in uscita
                     f"program={file.absolute()}",
                     f"description=Autofirewall generated rule at {time_iso} by Python process.",
                     *SETTINGS] ,
                    check=True
                )
                print(f"Traffico bloccato per: {file}")
        
        except subprocess.CalledProcessError as e:
            print(f"Errore durante la creazione delle regole del firewall: {e}")
            print("Assicurarsi di avere i privilegi di amministratore e che i comandi siano stati inseriti correttamente.")
            sys.exit(1)
        except Exception as ex:
            print(f"Si è verificato un errore imprevisto: {ex.with_traceback()}")
            sys.exit(1)


    @staticmethod
    def _text2dict(text: str):
        # Analizza l'output di netsh
        rules = []
        current_rule = {}
        for line in output_lines:
            if ":" in line:
                key, value = line.split(":", 1)
                
                key = key.strip().lower().replace(" ", "_")  # Pulisce la chiave per il dizionario
                value = value.strip()
                
                current_rule[key] = value
            elif "----" in line:  #fine della regola
                if current_rule:
                  rules.append(current_rule)
                current_rule = {} #resetta il dizionario

        if current_rule: #aggiunge l'ultima regola
            rules.append(current_rule)
        return rule_dict
        

    @classmethod
    def listrules(cls, options: list = []):
        """
        Elenca tutte le regole del firewall di Windows e le restituisce come una lista di dizionari.
        Ogni dizionario rappresenta una regola del firewall.
        """
        try:
            # Esegue il comando netsh per ottenere tutte le regole del firewall
            NETSH_CMD = cls.NETSH_LISTRULE_CMD + [*options, "verbose"]
            
            result = subprocess.run(NETSH_CMD, check=True, capture_output=True, text = True)                    
            output = result.stdout
            output_lines = [line.strip() for line in output.strip().split('\n') if line.strip() != ""]
    
            # Analizza l'output di netsh
            rules = []
            current_rule = {}
            for line in output_lines:
                if ":" in line:
                    key, value = line.split(":", 1)
                    key = key.strip().lower().replace(" ", "_")  # Pulisce la chiave per il dizionario
                    value = value.strip()
                    current_rule[key] = value
                elif "----" in line:  #fine della regola
                    if current_rule:
                      rules.append(current_rule)
                    current_rule = {} #resetta il dizionario
    
            if current_rule: #aggiunge l'ultima regola
                rules.append(current_rule)
            return rules
    
        except subprocess.CalledProcessError as e:
            print(f"Errore durante l'esecuzione del comando netsh: {e}")
            sys.exit(1)
        except Exception as ex:
            print(f"Si è verificato un errore imprevisto: {ex}")
            sys.exit(1)




    

if __name__ == "__main__":
    # Verifica i privilegi di amministratore prima di procedere.
    utility.run_as_admin()

    if len(sys.argv) > 1:

        folder_path = sys.argv[1]
        block_exe_traffic(folder_path)
        input("Done. Press to esc..")
    else:
        print(sys.argv)
        firewall_rules = list_firewall_rules()
