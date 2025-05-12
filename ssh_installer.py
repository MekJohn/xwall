import subprocess
import sys

def run_ssh_installer(choice=None):
    """
    Executes SSH installation/uninstallation tasks on Windows.

    Args:
        choice (int, optional): The operation to perform (0-7).
                                 If None, it will display a menu to the user.
                                 Defaults to None.
    """
    if sys.platform != "win32":
        print("This script is designed to run on Windows.")
        return

    if choice is None:
        print("WELCOME TO THE SSH INSTALLER UTILITY")
        print("-------------------------------------------")
        print("Choose what do you want to do:")
        print("0. Check SSH on this system")
        print("1. Install SSH Client")
        print("2. Install SSH Server")
        print("3. Install both SSH Client and Server")
        print("4. Uninstall SSH Client")
        print("5. Uninstall SSH Server")
        print("6. Uninstall both SSH Client and Server")
        print("7. Help")
        print("-------------------------------------------")
        while True:
            try:
                choice_str = input("Select the operation's number: ")
                choice = int(choice_str)
                if 0 <= choice <= 7:
                    break
                else:
                    print("Invalid choice. Please enter a number between 0 and 7.")
            except ValueError:
                print("Invalid input. Please enter a number.")

    if choice == 0:
        subprocess.run(["powershell", "-Command", "Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH*'"])
    elif choice == 1:
        subprocess.run(["powershell", "-Command", "Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0"])
    elif choice == 2:
        subprocess.run(["powershell", "-Command", "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0"])
        subprocess.run(["powershell", "-Command", "Start-Service sshd"])
        subprocess.run(["powershell", "-Command", "Set-Service -Name sshd -StartupType 'Automatic'"])
    elif choice == 3:
        subprocess.run(["powershell", "-Command", "Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0"])
        subprocess.run(["powershell", "-Command", "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0"])
    elif choice == 4:
        subprocess.run(["powershell", "-Command", "Remove-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0"])
    elif choice == 5:
        subprocess.run(["powershell", "-Command", "Remove-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0"])
    elif choice == 6:
        subprocess.run(["powershell", "-Command", "Remove-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0"])
        subprocess.run(["powershell", "-Command", "Remove-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0"])
    elif choice == 7:
        print("Connect server:\tssh username@servername")
        print("Copy files:\tscp -rpT <host@machine_name:/path> <to_local>")
        print("Copy tree:\txcopy <origin> <destination> /S /C /I /H /R /K /O /Y /B /J")
        print("Change drive:\tcd /D <drive:>")
        print("Manual CMD:\thelp")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        try:
            initial_choice = int(sys.argv[1])
            run_ssh_installer(initial_choice)
        except ValueError:
            print("Invalid argument. Please provide a number between 0 and 7.")
    else:
        run_ssh_installer()