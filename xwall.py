# XWALL 2025

import subprocess
import sys, os
import pathlib as pt
import time as tm

from pathlib import Path

from rich.progress import Progress
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
            # return rules


class DType(Enum):

    REG_SZ = winreg.REG_SZ
    REG_DWORD = winreg.REG_DWORD
    REG_BINARY = winreg.REG_BINARY
    REG_EXPAND_SZ = winreg.REG_EXPAND_SZ


class Address:

    def __init__(self, *parts: str):
        if not isinstance(parts, tuple):
            raise TypeError(f"Invalid argument: '{type(parts)}'.")

        self.core = tuple(str(p) for p in parts)

        if not self.core:
            raise ValueError(f"Invalid Address parts: {parts}")

    def __repr__(self):
        name = self.core[-1].encode(errors = "ignore").decode()
        return f"<Address '{name}'>"

    @property
    def path(self):
        path_str = "\\".join(self.core)
        return Path(path_str)

    # @staticmethod
    # def split(path: str):
    #     parts = path.split("\\")
    #     return parts

    @property
    def is_root(self):
        if len(self.core) > 1:
            return False
        else:
            root = self.core[0]
            hkeys = [h for h in HKEY.main().keys()]
            return True if root in hkeys else False

    @property
    def root(self):
        root = self.core[0]
        hkeys = [h for h in HKEY.main().keys()]
        return self.__class__(root) if root in hkeys else None

    @property
    def is_absolute(self):
        return True if self.root else False

    @property
    def is_relative(self):
        return not self.is_absolute

    @property
    def name(self):
        return self.core[-1]

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
        if isinstance(part, str):
            parts = self.core + (part,)
        elif isinstance(part, self.__class__):
            parts = self.core + part.core
        elif isinstance(part, Path):
            parts = self.core + tuple(p for p in part.parts)
        else:
            parts = self.core + (str(part),)
        return self.__class__(*parts)

    @property
    def relative(self):
        path = self.core[1:]
        return self.__class__(*path) if path else None

    @property
    def str(self):
        return str(self.path)

    @property
    def absolute(self):
        return self.__class__(*self.core) if self.is_absolute else None

    @property
    def location(self):
        if self.is_absolute:
            root = HKEY.main()[self.root.name]
            relative = self.relative
            sub_path = relative.str if relative else None
            return root, sub_path
        else:
            return None, None

    @property
    def parent(self):
        parent = self.core[:-1]
        return self.__class__(*parent)




class ABC:

    def __init__(self, address: Address):

        self.address = address
        if not self.address.is_absolute:
            raise ValueError(f"Invalid absolute Address: {address}")

    def __truediv__(self, other):
        address = self.address / other.address
        return self.__class__(address)

    def __repr__(self):
        return f"<ABC '{self.name}'>"


    @property
    def name(self):
        return self.address.name

    @property
    def is_root(self):
        return self.address.is_root

    @property
    def root(self):
        root_key = getattr(HKEY, self.address.root.name)()
        return root_key

    @property
    def parent(self):
        if self.address.is_root:
            return None
        else:
            parent = self.address.parent
            if parent.is_root:
                return getattr(HKEY, parent.name)()
            else:
                return FKEY(parent)

    @property
    def relative(self):
        relative = self.address.relative
        return relative if relative else None

    @property
    def info(self):
        with winreg.OpenKey(*self.address.location) as k:
            n_keys, n_values, mtime = winreg.QueryInfoKey(k)
            return n_keys, n_values, mtime

    @property
    def mtime(self):
        _, _, mtime = self.info
        return mtime

    # @property
    # def is_parent(self):
    #     fnum, _, _ = self.info
    #     return True if fnum > 0 else False


    @property
    def exists(self):
        try:
            with winreg.OpenKey(
                    *self.address.location, 0,
                    winreg.KEY_READ | winreg.KEY_WOW64_32KEY
                    ):
                return True
        except FileNotFoundError:
            try:
                with winreg.OpenKey(
                        *self.address.parent.location, 0,
                        winreg.KEY_READ | winreg.KEY_WOW64_32KEY
                        ) as k:
                    winreg.QueryValueEx(k, self.address.name)
                    return True
            except (FileNotFoundError, OSError, ValueError):
                return False
        except OSError:
            return False



class FKEY(ABC):

    def __init__(self, address: str):
        super().__init__(address)

    def __repr__(self):
        return f"<FKEY '{self.name}'>"

    @property
    def list(self):
        with winreg.OpenKey(
                *self.address.location, 0,
                winreg.KEY_READ | winreg.KEY_WOW64_32KEY) as k:

            numf, nume, _ = winreg.QueryInfoKey(k)
            fkeys = [winreg.EnumKey(k, i) for i in range(numf)]
            ekeys = [winreg.EnumValue(k, i) for i in range(nume)]
            return fkeys, ekeys


    @property
    def subf(self):
        found = []
        for name in self.list[0]:
            address = self.address / name
            fkey = FKEY(address)
            found.append(fkey)
        return found

    @property
    def sube(self):
        found = []
        for name, value, type_ in self.list[1]:
            address = self.address.absolute / name
            ekey = EKEY(address)
            found.append(ekey)
        return found

    @property
    def suba(self):
        return self.subf + self.sube

    def walk(self):
        try:
            for k in self.suba:
                yield k
                if isinstance(k, FKEY):
                    yield from k.walk()

        except (PermissionError, OSError):
            return None


    def delete(self, preview = True):
        if self.subf:
            for k in self.subf:
                k.delete(preview = preview)
        try:
            with winreg.OpenKey(*self.parent.address.location, 0,
                                winreg.KEY_ALL_ACCESS) as pkey:
                if not preview:
                    winreg.DeleteKey(pkey, self.name)
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

    def __init__(self, address: str):
        super().__init__(address)

    def __repr__(self):
        return f"<EKEY '{self.name}'>"



    @property
    def info(self):
        with winreg.OpenKey(*self.address.location) as k:
            value, type_ = winreg.QueryValueEx(k, self.name)
            return self.name, value, type_

    @property
    def value(self):
        return self.info[1]

    @property
    def type(self):
        return self.info[2]


    @property
    def is_parent(self):
        return False


    def delete(self, preview = True):
        try:
            with winreg.OpenKey(*self.parent.address.location, 0,
                                winreg.KEY_ALL_ACCESS) as pkey:
                if not preview:
                    winreg.DeleteKey(pkey, self.name)
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
        name_str = self.address.name.encode(errors = "ignore").decode()
        return f"<HKEY '{name_str}'>"


    def search(self, func: object):
        for k in self.walk():
            if func(k):
                yield k


    @classmethod
    def registries(cls):
        return [name for name, value in HKEY.items()]


    @classmethod
    def HKEY_USERS(cls):
        address = Address("HKEY_USERS")
        value = winreg.HKEY_USERS
        return cls(address, value)

    @classmethod
    def HKEY_CLASSES_ROOT(cls):
        address = Address("HKEY_CLASSES_ROOT")
        return cls(address, winreg.HKEY_CLASSES_ROOT)

    @classmethod
    def HKEY_CURRENT_CONFIG(cls):
        address = Address("HKEY_CURRENT_CONFIG")
        return cls(address, winreg.HKEY_CURRENT_CONFIG)

    @classmethod
    def HKEY_CURRENT_USER(cls):
        address = Address("HKEY_CURRENT_USER")
        return cls(address, winreg.HKEY_CURRENT_USER)

    @classmethod
    def HKEY_LOCAL_MACHINE(cls):
        address = Address("HKEY_LOCAL_MACHINE")
        return cls(address, winreg.HKEY_LOCAL_MACHINE)

    @staticmethod
    def main():
        keys = {
            "HKEY_CLASSES_ROOT": winreg.HKEY_CLASSES_ROOT,
            "HKEY_CURRENT_CONFIG": winreg.HKEY_CURRENT_CONFIG,
            "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
            "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
            "HKEY_USERS": winreg.HKEY_USERS
            }
        return keys



if __name__ == "__main__":

    # utility.run_as_admin()

    found = []
    func = lambda x: "autocad" in x.name.lower()
    hh = HKEY.HKEY_CURRENT_USER()

    # path_ek1 = r"HKEY_CLASSES_ROOT\*\folder1\fol/der2\C:/User\valor/doppio\spit"
    # path_ek2 = r"HKEY_CLASSES_ROOT\*\folder1\fol/der2\C:/User\valor/D:\cartella\spit"
    # path_fk = r"HKEY_CLASSES_ROOT\*\folder\val/ore\C:/User\fold/er"

    # aa = Address("HKEY_CLASSES_ROOT", "folder", r"doppio\spit")
    # bb = Address("HKEY_CLASSES_ROOT", "folder1",
    #              "fol/der2","C:/User", r"D:\cartella\spit")

    found = []
    for i, k in enumerate(hh.walk()):
        print(f"{i:0>10}. {k.address.core}")
        if ("autocad" in k.name.lower()
            or "autolisp" in k.name.lower()
            or "autodesk" in k.name.lower()
            ):
            found.append(k)


