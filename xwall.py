# XWALL 2025

import subprocess
import sys
import pathlib as pt
import time as tm

import utility
from enum import Enum
import winreg
from dataclasses import dataclass, field as Field



class Netsh:

    NETSH_ADDRULE_CMD = ["netsh", "advfirewall", "firewall", "add", "rule"]
    NETSH_LISTRULE_CMD = ["netsh", "advfirewall", "firewall", "show rule", "name=all"]

    @staticmethod
    def rules_to_dict(text_rules: str):
        # Analizza l'output di netsh
        rules = []
        current_rule = {}
        for line in text_rules:
            if ":" in line:
                key, value = line.split(":", 1)
                # init data
                key = key.strip().lower().replace(" ", "_")  # Pulisce la chiave per il dizionario
                value = value.strip()
                # add rule feature to the rule dict
                current_rule[key] = value
            elif "----" in line:  #fine della regola
                if current_rule:
                  rules.append(current_rule)
                current_rule = {} #resetta il dizionario

        if current_rule: #aggiunge l'ultima regola
            rules.append(current_rule)
        return rules


class Firewall:

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
                print(f"Errore: La cartella specificata '{path}' non esiste.")
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



    @classmethod
    def listrules(cls, options: list = [], xwall_rules_only: bool = False):
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
            rules = cls._rules2dict(output_lines)

        except subprocess.CalledProcessError as e:
            print(f"Errore durante l'esecuzione del comando netsh: {e}")
            sys.exit(1)
        except Exception as ex:
            print(f"Si è verificato un errore imprevisto: {ex}")
            sys.exit(1)
        finally:
            rules = rules if rules is not None else []
            return rules


class DType(Enum):

    REG_SZ = winreg.REG_SZ
    REG_DWORD = winreg.REG_DWORD
    REG_BINARY = winreg.REG_BINARY
    REG_EXPAND_SZ = winreg.REG_EXPAND_SZ

class HKEY(Enum):

    HKEY_USERS = winreg.HKEY_USERS
    HKEY_CLASSES_ROOT = winreg.HKEY_CLASSES_ROOT
    HKEY_CURRENT_USER = winreg.HKEY_CURRENT_USER
    HKEY_LOCAL_MACHINE = winreg.HKEY_LOCAL_MACHINE
    HKEY_CURRENT_CONFIG = winreg.HKEY_CURRENT_CONFIG

@dataclass
class FKEY:

    name: str = None
    root: str = Field(repr = False, default = None)
    path: str = Field(repr = False, default = str)
    mtime: int = Field(repr = False, default = None)

    @property
    def info(self):
        with winreg.OpenKey(self.root.value, self.path) as k:
            n_keys, n_values, mtime = winreg.QueryInfoKey(k)
            return n_keys, n_values, mtime

    @property
    def subf(self):
        sub_fkeys = []
        with winreg.OpenKey(self.root.value, self.path) as k:
            n_keys, _, mtime = winreg.QueryInfoKey(k)
            for s in range(n_keys):
                name = winreg.EnumKey(k, s)
                path = self.path + "\\" + name
                fkey = FKEY(root = self.root, name = name, path = path)
                sub_fkeys.append(fkey)
        return sub_fkeys

    @property
    def sube(self):
        sub_ekeys = []
        with winreg.OpenKey(self.root.value, self.path) as k:
            _, n_entry, mtime = winreg.QueryInfoKey(k)
            for e in range(n_entry):
                name, value, dtype = winreg.EnumValue(k, e)
                path = self.path + "\\" + name
                dtype = DType(dtype) if dtype in DType else dtype
                ekey = EKEY(
                    root = self.root, path = path,
                    name = name, value = value, dtype = dtype,
                    )
                sub_ekeys.append(ekey)
        return sub_ekeys

    @property
    def data(self):
        with winreg.OpenKey(self.value, "") as k:
            n_keys, n_values, mtime = winreg.QueryInfoKey(k)
            return n_keys, n_values, mtime

@dataclass
class EKEY:

    name: str = None
    dtype: str | int = Field(repr = False, default = None)
    value: str | int = Field(repr = False, default = None)

    root: str = Field(repr = False, default = None)
    path: str = Field(repr = False, default = str)
    mtime: int = Field(repr = False, default = None)


class WinREG:

    def __init__(self):
        pass

    @property
    def HKEY(self):
        return HKEY

    def items(self):
        items = {root.name: root.value for root in self.HKEY}
        return items

    def key_info(key: int):
        with winreg.OpenKey(key.value, "") as k:
            n_keys, n_values, mtime = winreg.QueryInfoKey(k)
            return n_keys, n_values, mtime


    def listreg(self, key: HKEY):
        with winreg.OpenKey(key.value, "") as k:
            n_fkeys, n_ekeys, mtime = winreg.QueryInfoKey(k)
            fkeys = []
            ekeys = []

            for f in range(n_fkeys):
                name = winreg.EnumKey(k, f)
                path = "\\" + name
                fkey = FKEY(root = key, name = name, path = path, mtime = mtime)
                fkeys.append(fkey)

            for e in range(n_ekeys):
                name, value, dtype = winreg.EnumValue(k, e)
                path = self.path + "\\" + name
                dtype = DType(dtype) if dtype in DType else dtype
                ekey = EKEY(
                    root = self.root, path = path,
                    name = name, value = value, dtype = dtype,
                    )
                ekeys.append(ekey)

            keys = [*fkeys, *ekeys]
            return keys






class Xreg:

    @classmethod
    def cerca_nel_registro(cls, parola_chiave):
        import winreg
        risultati = []
        # Definiamo le radici principali da scansionare
        roots = HKEY.list()

        for nome_root, hkey in roots.items():
            print(f"Scansione di {nome_root} in corso...")
            cls._scansiona_ricorsivamente(hkey, "", parola_chiave, risultati, nome_root)

        return risultati

    @classmethod
    def _scansiona_ricorsivamente(cls, hkey, percorso, target, lista_risultati, root_name):
        import winreg
        try:
            with winreg.OpenKey(hkey, percorso) as chiave:
                # 1. Controlla i VALORI all'interno di questa chiave
                info = winreg.QueryInfoKey(chiave)
                num_values = info[1]
                for i in range(num_values):
                    nome_val, dato_val, tipo_val = winreg.EnumValue(chiave, i)
                    if target.lower() in str(nome_val).lower() or target.lower() in str(dato_val).lower():
                        lista_risultati.append(f"{root_name}\\{percorso} -> {nome_val}: {dato_val}")

                # 2. Esplora le SOTTOCHIAVI (Ricorsione)
                num_keys = info[0]
                for i in range(num_keys):
                    nome_sottochiave = winreg.EnumKey(chiave, i)
                    nuovo_percorso = f"{percorso}\\{nome_sottochiave}" if percorso else nome_sottochiave

                    # Se il nome della chiave contiene la parola, aggiungila
                    if target.lower() in nome_sottochiave.lower():
                        lista_risultati.append(f"{root_name}\\{nuovo_percorso}")

                    # Continua la ricerca in profondità
                    cls._scansiona_ricorsivamente(hkey, nuovo_percorso, target, lista_risultati, root_name)

        except PermissionError:
            # Molte chiavi di sistema sono protette, le saltiamo
            pass
        except OSError:
            pass




if __name__ == "__main__":
    # Verifica i privilegi di amministratore prima di procedere.
    utility.run_as_admin()

    # Esempio di utilizzo
    parola = "autocad"
    trovati = Xreg.cerca_nel_registro(parola)

    print(f"\nRisultati trovati per '{parola}': {len(trovati)}")
    for item in trovati[:10]: # Mostra i primi 10 per brevità
        print(item)
        input()



    # console_args = sys.argv

    # if len(console_args) > 1:

    #     path = console_args[1]
    #     Firewall.block_traffic(path)
    #     input("Done. Press to esc..")
    # else:
    #     print(console_args)
    #     firewall_rules = Firewall.listrules()
