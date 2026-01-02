<#
.SYNOPSIS
    Installs PowerShell 7 (MSI) silently alongside Windows PowerShell 5.1.
#>

Write-Host "--- INSTALLING POWERSHELL 7 ---" -ForegroundColor Cyan

# Check if already installed
if (Get-Command pwsh -ErrorAction SilentlyContinue) {
    $ver = (pwsh -v)
    Write-Host "PowerShell 7 is already installed: $ver" -ForegroundColor Green
    return
}

Write-Host "Downloading and installing... (This may take 1-2 minutes)" -ForegroundColor Yellow

# Use Microsoft's official install script
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    & { iex "& { $(irm https://aka.ms/install-powershell.ps1) } -UseMSI -Quiet" }
    
    Write-Host "Installation command sent." -ForegroundColor Green
    Write-Host "Note: You may need to restart your shell to use 'pwsh'." -ForegroundColor Gray
}
catch {
    Write-Error "Install failed: $($_.Exception.Message)"
}