Write-Output "Do you want to enable Teredo? (y/n)"
$confirm = Read-Host
if ($confirm -eq "y") {
    netsh interface teredo set state enabled
}
else {
    Write-Output "Teredo will not be enabled."
}