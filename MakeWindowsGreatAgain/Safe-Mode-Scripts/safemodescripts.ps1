#Removes Microsoft Edge
Write-Output "Do you want to uninstall Microsoft Edge? (y/n)"
$confirm = Read-Host

if ($confirm -eq "y") {
    Write-Output "Uninstalling Microsoft Edge and removing all its non-essential related components."
    Remove-Item "C:\Program Files (x86)\Microsoft\Edge"
    Remove-Item "C:\Program Files (x86)\Microsoft\EdgeCore"
    Remove-Item "C:\Program Files (x86)\Microsoft\EdgeUpdate"
} else {
    Write-Output "Microsoft Edge will not be uninstalled."
}
timeout /t 5