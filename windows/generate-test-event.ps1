# Run only in the Windows lab VM after Sysmon and event collection are configured.
$socLabText = "Write-Output 'SOC-LAB-P1'"
$socLabEncoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($socLabText))
powershell.exe -NoProfile -EncodedCommand $socLabEncoded
