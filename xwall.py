# XWALL 2025

import subprocess
import sys, os
import pathlib as pt
import time as tm

from pathlib import Path

from rich.progress import track
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


class Address:

    def __init__(self, path: str | Path):
        self.core = self._to_path(path)

        if not self.core.parts:
            raise ValueError(f"Invalid Address: {str(self.core)}")

    def __repr__(self):
        return f"<Address '{self.name}'>"


    @property
    def root(self):
        root_str = self.core.parts[0]
        hkeys = [h for h in HKEY.main().keys()]
        return self.__class__(root_str) if root_str in hkeys else None

    @property
    def is_root(self):
        return True if self.root else False

    @property
    def is_absolute(self):
        return True if self.root else False

    @property
    def is_relative(self):
        return not self.is_absolute


    @property
    def name(self):
        name = self.core.name.encode(errors = "ignore").decode()
        name = "" if not name or name == "."else name
        return name

    @classmethod
    def _to_path(cls, path):
        if isinstance(path, cls):
            path = path.core
        elif isinstance(path, str):
            path = Path(path)
        elif path is None:
            path = Path()
        else:
            path = Path(str(path))
        return path

    def __truediv__(self, part):
        base = self.core
        tail = self._to_path(part)

        if tail.drive:
            new_address = f"{base.as_posix()}/{tail.as_posix()}"
            new_address = Path(new_address)
        else:
            new_address = self.core / tail
        return self.__class__(new_address)

    @property
    def relative(self):
        path_str = str(self.core).split(self.root.name)[1].strip("/").strip("\\")
        path = None if path_str in ["", "."] else path_str
        return self.__class__(path) if path else None

    @property
    def str(self):
        return str(self.core)

    @property
    def absolute(self):
        return self.__class__(self.core) if self.is_absolute else None

    @property
    def parent(self):
        parent = self.core.parent
        return None if parent == Path() else self.__class__(parent)




class ABC:

    def __init__(self, address: str):
        if address.is_absolute:
            self.address: str = Address(address)
        else:
            raise ValueError(f"Invalid absolute Address: {address}")

    @property
    def name(self):
        return self.address.name

    def __truediv__(self, other):
        address = self.address / other.address
        return self.__class__(name = address.name, address=address)

    def __repr__(self):
        return f"<ABC '{self.name}'>"

    @property
    def root(self):
        root_key = getattr(HKEY, self.address.root.name)()
        return root_key

    @property
    def parent(self):
        return None if self.is_root else self.__class__(self.address.parent)

    @property
    def relative(self):
        relative = self.address.relative
        return relative if relative else None

    @property
    def info(self):
        relative = self.address.relative
        sub_path = relative.str if relative else None
        with winreg.OpenKey(self.root.value, sub_path) as k:
            n_keys, n_values, mtime = winreg.QueryInfoKey(k)
            return n_keys, n_values, mtime

    @property
    def mtime(self):
        _, _, mtime = self.info
        return mtime

    @property
    def is_parent(self):
        fnum, enum, _ = self.info
        return True if fnum + enum > 0 else False


    @property
    def exists(self):
        try:
            with winreg.OpenKey(self.root.value, str(self.rel_path)):
                return True
        except FileNotFoundError:
            return False






class FKEY(ABC):

    def __init__(self, address: str):
        super().__init__(address)

    def __repr__(self):
        return f"<FKEY '{self.name}'>"

    @property
    def is_root(self):
        return self.address.is_root

    @property
    def subf(self):
        found = []
        relative = self.address.relative
        sub_path = relative.str if relative else None
        with winreg.OpenKey(self.root.value, sub_path) as k:
            n_keys, _, mtime = winreg.QueryInfoKey(k)
            for s in range(n_keys):
                name = winreg.EnumKey(k, s)
                address = self.address.absolute / name
                fkey = FKEY(address = address)
                found.append(fkey)
        return found

    @property
    def sube(self):
        found = []
        relative = self.address.relative
        sub_path = relative.str if relative else None
        with winreg.OpenKey(self.root.value, sub_path) as k:
            _, n_entry, mtime = winreg.QueryInfoKey(k)
            for e in range(n_entry):
                name, value, dtype = winreg.EnumValue(k, e)
                dtype = DType(dtype) if dtype in DType else dtype
                address = self.address.absolute / name
                ekey = EKEY(address, dtype, value)
                found.append(ekey)
        return found

    @property
    def suba(self):
        return self.subf + self.sube

    def walk(self, mode = "all"):
        try:
            for e in self.sube:
                yield e

            for f in self.subf:
                yield f
                yield from f.walk()

        except (PermissionError, OSError):
            return

    @property
    def is_parent(self):
        fnum, enum, _ = self.info
        return True if fnum + enum > 0 else False

    def __enter__(path: str, mode: str = "r"):
        pass


    def delete(self, preview = True):
        if self.is_parent:
            return False

        root = self.root.value
        parent = str(self.parent.address)
        full_access = winreg.KEY_ALL_ACCESS

        try:
            with winreg.OpenKey(root, parent, 0, full_access) as parent_key:
                if not preview:
                    winreg.DeleteKey(parent_key, self.name)
                print(f"Deleted: {self.name}")
                return True
        except FileNotFoundError:
            return True
        except PermissionError:
            print(f"PermissionError: {self.address}.")
            return False
        except Exception as e:
            print(f"GeneralError: {e}")
            return False

    def delete_tree(self, preview = True):
        items_to_delete = [self] + list(self.walk())
        items_to_delete.reverse()

        while items_to_delete:
            for i, item in enumerate(items_to_delete):
                deleted = item.delete(preview = preview)
                if deleted:
                    items_to_delete.pop(i)
                    break
                else:
                    subitems = list(item.walk())
                    items_to_delete.extend(subitems)
        return False if items_to_delete else True



class EKEY(ABC):

    def __init__(self, address: str, dtype: object | int, value: str):

        super().__init__(address)
        self.dtype = dtype
        self.value = value

    def __repr__(self):
        return f"<EKEY '{self.name}'>"


    @property
    def is_parent(self):
        return False


    def delete(self, preview = True):
        if self.is_parent:
            return False

        root = self.root.value
        parent = str(self.parent.address)
        full_access = winreg.KEY_ALL_ACCESS

        try:
            with winreg.OpenKey(root, parent, 0, full_access) as parent_key:
                if not preview:
                    winreg.DeleteValue(parent_key, self.name)
                print(f"Deleted: {self.name}")
                return True
        except FileNotFoundError:
            return True
        except PermissionError:
            print(f"PermissionError: {self.address}.")
            return False
        except Exception as e:
            print(f"GeneralError: {e}")
            return False



class HKEY(FKEY):

    def __init__(self, address: str, value: str):

        super().__init__(address)
        self.value = value

    def __repr__(self):
        name_str = self.name.encode(errors = "ignore").decode()
        return f"<HKEY '{name_str}'>"


    def search(self, func: object):
        for k in self.walk():
            if func(k):
                yield k


    @classmethod
    def HKEY_USERS(cls):
        address = Address("HKEY_USERS")
        value = winreg.HKEY_USERS
        return cls(address, value)

    @classmethod
    def HKEY_CLASSES_ROOT(cls):
        address = Address("HKEY_CLASSES_ROOT")
        value = winreg.HKEY_CLASSES_ROOT
        return cls(address, value)

    @classmethod
    def HKEY_CURRENT_CONFIG(cls):
        address = Address("HKEY_CURRENT_CONFIG")
        value = winreg.HKEY_CURRENT_CONFIG
        return cls(address, value)

    @classmethod
    def HKEY_CURRENT_USER(cls):
        address = Address("HKEY_CURRENT_USER")
        value = winreg.HKEY_CURRENT_USER
        return cls(address, value)

    @classmethod
    def HKEY_LOCAL_MACHINE(cls):
        address = Address("HKEY_LOCAL_MACHINE")
        value = winreg.HKEY_LOCAL_MACHINE
        return cls(address, value)

    @classmethod
    def walk(cls, *hkeys: object):
        hkeys = cls.main() if not hkeys else hkeys
        for h in hkeys:
            for k in h.all:
                for s in k.walk():
                    yield s

    @staticmethod
    def main():
        return {
            "HKEY_CLASSES_ROOT": winreg.HKEY_CLASSES_ROOT,
            "HKEY_CURRENT_CONFIG": winreg.HKEY_CURRENT_CONFIG,
            "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
            "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
            "HKEY_USERS": winreg.HKEY_USERS
            }



if __name__ == "__main__":

    # utility.run_as_admin()

    found = []
    func = lambda x: "autocad" in x.name.lower()
    hh = HKEY.HKEY_CLASSES_ROOT()
    for k in hh.subf:
        print(k.info)

    aa = hh.address / "ciao" / "oiuhoipsjpois" / r"\\192.168.1.110\Server UTN\Commesse\2025\MKP - F25-0428 - NENCINI\Docs\MAIL - nuova richiesta cliente.pdf" / r"C:\Users\Ing. Gaudio\Downloads\RO250180.pdf" / "Iuhiuhih.png"


