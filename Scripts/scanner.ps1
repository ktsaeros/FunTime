# Require Administrator privileges
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "You must run this script as Administrator!"
    Exit
}

$ErrorActionPreference = "Stop"

# --- Configuration ---
$userName = "scans"
$userPass = "scans" 
$folderPath = "C:\Scans"
$shareName = "Scans"

Write-Host "Starting Scanner Setup on $(hostname)..." -ForegroundColor Cyan

# 1. Create the Local User
try {
    if (Get-LocalUser -Name $userName -ErrorAction SilentlyContinue) {
        Write-Host "User '$userName' already exists. Resetting password..." -ForegroundColor Yellow
        $securePass = ConvertTo-SecureString $userPass -AsPlainText -Force
        Set-LocalUser -Name $userName -Password $securePass
    } else {
        Write-Host "Creating user '$userName'..." -ForegroundColor Green
        $securePass = ConvertTo-SecureString $userPass -AsPlainText -Force
        New-LocalUser -Name $userName -Password $securePass -FullName "Scanner Service Account" -Description "Account for Ricoh SMB Scanning"
    }
    # Set Password to Never Expire
    Set-LocalUser -Name $userName -PasswordNeverExpires $true
}
catch {
    Write-Error "Failed to manage user account: $_"
}

# 2. Hide User from Login Screen (Registry)
try {
    Write-Host "Hiding user '$userName' from login screen..." -ForegroundColor Green
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"
    
    if (!(Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }

    New-ItemProperty -Path $regPath -Name $userName -Value 0 -PropertyType DWORD -Force | Out-Null
}
catch {
    Write-Error "Failed to modify registry to hide user: $_"
}

# 3. Create Folder and Set NTFS Permissions
try {
    if (!(Test-Path $folderPath)) {
        Write-Host "Creating folder '$folderPath'..." -ForegroundColor Green
        New-Item -Path $folderPath -ItemType Directory | Out-Null
    }

    Write-Host "Setting NTFS permissions..." -ForegroundColor Green
    $acl = Get-Acl -Path $folderPath
    $permission = "$userName","FullControl","ContainerInherit,ObjectInherit","None","Allow"
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
    $acl.AddAccessRule($accessRule)
    Set-Acl -Path $folderPath -AclObject $acl
}
catch {
    Write-Error "Failed to set folder permissions: $_"
}

# 4. Create SMB Share
try {
    if (Get-SmbShare -Name $shareName -ErrorAction SilentlyContinue) {
        Write-Host "Share '$shareName' already exists. Ensuring permissions..." -ForegroundColor Yellow
        Grant-SmbShareAccess -Name $shareName -AccountName $userName -AccessRight Full -Force | Out-Null
    } else {
        Write-Host "Creating SMB Share '$shareName'..." -ForegroundColor Green
        New-SmbShare -Name $shareName -Path $folderPath -FullAccess $userName -Description "Ricoh Scans" | Out-Null
    }
}
catch {
    Write-Error "Failed to create SMB Share: $_"
}

# 5. Network Profile & Firewall
# --- NEW SECTION ADDED HERE ---
try {
    Write-Host "Forcing Network Profile to Private..." -ForegroundColor Green
    Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private
    
    Write-Host "Verifying Firewall rules for File Sharing..." -ForegroundColor Green
    Enable-NetFirewallRule -DisplayGroup "File and Printer Sharing" -ErrorAction SilentlyContinue
}
catch {
    Write-Warning "Could not configure Network/Firewall. Please check manually."
}

Write-Host "Setup Complete! Ricoh Path: \\$(hostname)\$shareName" -ForegroundColor Cyan