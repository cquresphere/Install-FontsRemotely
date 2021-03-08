# Install-FontsRemotely
Installing remotely fonts to computers using Powershell and PsExec.

# Requirements:

- Powershell v5 and above
- PsExec
- WINRM service (triggerd by Psexec) 
- List of host to install fonts
- Location with fonts
- Location on remote computers to download fonts for installation.

# Script

Script uses WINRM service to install perform installation remotely. 
PsExec allows to meets all prerequisites to run WINRM on remote computer. 
