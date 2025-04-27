# XWALL 2025

import sys
import ctypes
import pathlib as pt

def is_admin():
    """
    Verifica se lo script è in esecuzione con privilegi di amministratore.
    Restituisce True se l'utente è un amministratore, False altrimenti.
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin(executable: str = None, argv: list = None):
    """
    Riavvia lo script con privilegi di amministratore.
    """
    # TODO i percorsi devono essere assoluti altrimenti non trova nulla
    python_executable = sys.executable
    script_path = pt.Path(sys.argv[0]).resolve()
    script_arguments = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else ""
                 
    if not is_admin():
        print("Richiesta di privilegi di amministratore...")
        print(f"{python_executable}\n{script_path}\n{script_arguments}")
        arguments_to_pass = f'"{script_path}" {script_arguments}'
        returned = ctypes.windll.shell32.ShellExecuteW(None, "runas", python_executable, arguments_to_pass, None, 1)
        
        print(returned)
        success = True if int(returned) > 32 else False
        if success:
            print("Ran as admin correctly.")
        else:
            print("Failed to run as admin.")
        sys.exit()