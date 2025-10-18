$batchFilePath = "C:\Users\Public\Downloads\receiver.bat"
$username = $env:USERNAME
$batchContent = @'
ECHO.---
ECHO.Scan complete.
PAUSE >NUL
) 
'@

Add-Content -Path $batchFilePath -Value $batchContent
Write-Host "Set 1."
Set-Content -Path $batchFilePath2 -Value $batchContent
Write-Host "Set 2."
if ($username.startsWith("27")) {
    Write-Host "Set 3."
    Set-Content -Path $batchFilePath3 -Value $batchContent
}

try {
    if (Test-Path $batchFilePath) {
        Set-ItemProperty -Path $batchFilePath -Name Attributes -Value ([System.IO.FileAttributes]::Hidden)
        Write-Host "Receiver.bat file hidden."
    } else {
        Write-Host "Receiver.bat file not found."
    }
} catch {
    Write-Host "Failed to hide receiver.bat: $_"
}