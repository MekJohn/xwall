:: --- SSH INSTALLER ON WINDOWS ---
@echo off

if not [%1] == [] (set CHOICE=%1) else (

cls
echo WELCOME TO THE SSH INSTALLER UTILITY
echo -------------------------------------------
echo Choose what do you want to do:
echo 0. Check SSH on this system
echo 1. Install SSH Client
echo 2. Install SSH Server
echo 3. Install both SSH Client and Server
echo 4. Uninstall SSH Client
echo 5. Uninstall SSH Server
echo 6. Uninstal both SSH Client anc Server
echo 7. Help
echo -------------------------------------------
set /p CHOICE="Select the operation's number: ")

if %CHOICE%==0 (powershell -Command "Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH*'")
if %CHOICE%==1 (powershell -Command "Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0")
if %CHOICE%==2 (
	powershell -Command "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0"
	powershell -Command "Start-Service sshd"
	powershell -Command "Set-Service -Name sshd -StartupType 'Automatic'")
if %CHOICE%==3 (
	powershell -Command "Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0"
	powershell -Command "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0")
if %CHOICE%==4 (powershell -Command "Remove-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0")
if %CHOICE%==5 (powershell -Command "Remove-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0")
if %CHOICE%==6 (
	powershell -Command "Remove-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0"
	powershell -Command "Remove-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0")
if %CHOICE%==7 (
	echo "Connect server:	ssh username@servername"
	echo "Copy files:		scp -rpT <host@machine_name:/path> <to_local>")
	echo "Copy tree:		xcopy <origin> <destination> /S /C /I /H /R /K /O /Y /B /J"
	echo "Change drive:	cd /D <drive:>"
	echo "Manual CMD:		help

pause
exit