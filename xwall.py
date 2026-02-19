# XWALL 2025

import subprocess
import sys
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

    def __init__(self, root: "HKEY", path: str = None):
        path = "." if path is None else path
        self.core = Path(path)
        self.root = root

    def __repr__(self):
        name_str = self.core.name.encode(errors = "ignore").decode()
        if not name_str or name_str == ".":
            name_str = self.root.name

        return f"<Address '{name_str}'>"

    def __divmod__(self, part):
        base = self.core.as_posix()
        if isinstance(part, self.__class__):
            tail = part.core.as_posix()
        elif isinstance(part, Path):
            tail = part.as_posix()
        elif isinstance(part, str):
            tail = Path(part)
        elif part is None:
            tail = Path()
        else:
            tail = Path(str(part))

        if tail.drive:
            base = self.core.base.as_posix()
            tail = part.as_posix()
            new_address = f"{base}//{tail}"
        else:
            new_address = self.core // tail
        return self.__class__(new_address)


    def _join(self, tail):
        if tail.drive:
            return self.__class__(f"{self.base.as_posix}//{tail.as_posix}")
        else:
            return self.__class__(self // tail)


class FKEY:

    def __init__(self, name: str = None, address: str = None):

        self.name: str = name
        self.address: str = Path(address)

    def __repr__(self):
        name_str = self.name.encode(errors = "ignore").decode()
        return f"<FKEY '{name_str}'>"

    @property
    def root(self):
        name = self.address.parts[0]
        root = getattr(HKEY, name)()
        return root

    @property
    def parent(self):
        if self.address == self.root.address:
            return self.root
        else:
            parent_addr = self.address.parent
            parent_name = parent_addr.name
        return self.__class__(name = parent_name, address = parent_addr)

    @property
    def abs_path(self):
        return self.address

    @property
    def rel_path(self):
        path = self.address.relative_to(self.root.name)
        return None if path == Path(".") or path is None else path

    @property
    def info(self):
        rel_path = None if self.rel_path is None else str(self.rel_path)
        with winreg.OpenKey(self.root.value, rel_path) as k:
            n_keys, n_values, mtime = winreg.QueryInfoKey(k)
            return n_keys, n_values, mtime

    @property
    def mtime(self):
        _, _, mtime = self.info
        return mtime

    @property
    def subf(self):
        sub_fkeys = []
        rel_path = None if self.rel_path is None else str(self.rel_path)
        with winreg.OpenKey(self.root.value, rel_path) as k:
            n_keys, _, mtime = winreg.QueryInfoKey(k)
            for s in range(n_keys):
                name = winreg.EnumKey(k, s)
                address = self._join(self.abs_path, name)
                fkey = FKEY(name = name, address = address)
                sub_fkeys.append(fkey)
        return sub_fkeys

    @property
    def sube(self):
        sub_ekeys = []
        rel_path = None if self.rel_path is None else str(self.rel_path)
        with winreg.OpenKey(self.root.value, rel_path) as k:
            _, n_entry, mtime = winreg.QueryInfoKey(k)
            for e in range(n_entry):
                name, value, dtype = winreg.EnumValue(k, e)
                dtype = DType(dtype) if dtype in DType else dtype,
                address = self._join(self.abs_path, name)
                ekey = EKEY(
                    name = name, value = value,
                    dtype = dtype, address = address,
                    )
                sub_ekeys.append(ekey)
        return sub_ekeys

    @property
    def all(self):
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


    @property
    def exists(self):
        try:
            with winreg.OpenKey(self.root.value, str(self.rel_path)):
                return True
        except FileNotFoundError:
            return False



class EKEY:

    def __init__(self, name: str = None, address: str = None,
                 dtype: object | int = None, value: str = None):

        self.name = name
        self.address = Path(address)
        self.dtype = dtype
        self.value = value

    def __repr__(self):
        name_str = self.name.encode(errors = "ignore").decode()
        return f"<EKEY '{name_str}'>"

    @property
    def root(self):
        name = self.address.parts[0]
        root = getattr(HKEY, name)()
        return root

    @property
    def parent(self):
        if self.address == self.root.address:
            return self.root
        else:
            parent_addr = self.address.parent
            parent_name = parent_addr.name
        return self.__class__(name = parent_name, address = parent_addr)

    @property
    def abs_path(self):
        return self.address

    @property
    def rel_path(self):
        path = self.address.relative_to(self.root.name)
        return None if path == Path(".") or path is None else path

    @property
    def info(self):
        rel_path = None if self.rel_path is None else str(self.rel_path)
        with winreg.OpenKey(self.root.value, rel_path) as k:
            n_keys, n_values, mtime = winreg.QueryInfoKey(k)
            return n_keys, n_values, mtime

    @property
    def is_parent(self):
        return False

    @property
    def mtime(self):
        _, _, mtime = self.info
        return mtime

    @property
    def exists(self):
        try:
            with winreg.OpenKey(self.root.value, str(self.rel_path)):
                return True
        except FileNotFoundError:
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

    def __init__(self, name: str = None, address: str = None,
                 value: str = None):

        super().__init__(name = name, address = address)
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
        name, value = "HKEY_USERS", winreg.HKEY_USERS
        return cls(name = name, address = name, value = value)

    @classmethod
    def HKEY_CLASSES_ROOT(cls):
        name, value = "HKEY_CLASSES_ROOT", winreg.HKEY_CLASSES_ROOT
        return cls(name = name, address = name, value = value)

    @classmethod
    def HKEY_CURRENT_CONFIG(cls):
        name, value = "HKEY_CURRENT_CONFIG", winreg.HKEY_CURRENT_CONFIG
        return cls(name = name, address = name, value = value)

    @classmethod
    def HKEY_CURRENT_USER(cls):
        name, value = "HKEY_CURRENT_USER", winreg.HKEY_CURRENT_USER
        return cls(name = name, address = name, value = value)

    @classmethod
    def HKEY_LOCAL_MACHINE(cls):
        name, value = "HKEY_LOCAL_MACHINE", winreg.HKEY_LOCAL_MACHINE
        return cls(name = name, address = name, value = value)

    @classmethod
    def walk(cls, *hkeys: object):
        hkeys = cls.list() if not hkeys else hkeys
        for h in hkeys:
            for k in h.all:
                for s in k.walk():
                    yield s

    @classmethod
    def list(cls):
        return [
            cls.HKEY_USERS(), cls.HKEY_CURRENT_USER(),
            cls.HKEY_CLASSES_ROOT(), cls.HKEY_CURRENT_CONFIG(),
            cls.HKEY_LOCAL_MACHINE()
            ]



if __name__ == "__main__":

    # utility.run_as_admin()

    found = []
    func = lambda x: "autocad" in x.name.lower()
    hh = HKEY.HKEY_CURRENT_CONFIG()
    # found[0].delete_tree()


