$ErrorActionPreference = 'Stop'

# Admin check
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run in an elevated PowerShell session."
}

# Cmdlets present?
if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
    throw "BitLocker PowerShell module not available on this system."
}

# TPM ready?
$tpm = Get-Tpm
if (-not $tpm.TpmReady) { throw "TPM is not ready. Aborting." }

$Drive  = 'C:'
$RegPath = 'HKLM:\SOFTWARE\AerosIT\BitLocker'
$RegKey  = Join-Path $RegPath 'C'

# Ensure registry path
if (-not (Test-Path $RegPath)) { New-Item -Path $RegPath -Force | Out-Null }
if (-not (Test-Path $RegKey))  { New-Item -Path $RegKey  -Force | Out-Null }

function Get-OrAddRecoveryPassword {
    param([string]$MountPoint)

    $v = Get-BitLockerVolume -MountPoint $MountPoint
    $existing = $v.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }
    if ($existing) {
        return [pscustomobject]@{
            NewlyCreated     = $false
            RecoveryPassword = $null
            ProtectorId      = $existing[0].KeyProtectorId
        }
    }

        $added = Add-BitLockerKeyProtector -MountPoint $MountPoint -RecoveryPasswordProtector
    $pw  = $added.RecoveryPassword
    $ProtId = if ($added.KeyProtector) { $added.KeyProtector.KeyProtectorId } else { $null }

    if (-not $pw) {
        $txt = (manage-bde -protectors -get $MountPoint | Out-String)
        $pw  = ($txt -split "`r?`n" | Where-Object { $_ -match '^\s*Numerical Password:\s*([0-9-]+)\s*$' } |
               ForEach-Object { ($_ -split ':')[1].Trim() }) | Select-Object -First 1
    }

    if (-not $pw) { throw "Failed to capture a new recovery password." }

    if (-not $ProtId) {
        $v2 = Get-BitLockerVolume -MountPoint $MountPoint
        $ProtId = ($v2.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' } |
               Select-Object -First 1 -ExpandProperty KeyProtectorId)
    }

    [pscustomobject]@{
        NewlyCreated     = $true
        RecoveryPassword = $pw
        ProtectorId      = $ProtId
    }
}

$bv = Get-BitLockerVolume -MountPoint $Drive
$info = $null

if ($bv.ProtectionStatus -eq 'Off' -and $bv.VolumeStatus -ne 'EncryptionInProgress') {
    Write-Host "Enabling BitLocker on $Drive with TPM + Recovery Password (UsedSpaceOnly)..."
    $info = Get-OrAddRecoveryPassword -MountPoint $Drive
    Enable-BitLocker -MountPoint $Drive -TpmProtector -SkipHardwareTest -UsedSpaceOnly -EncryptionMethod XTSAes256
    Write-Host "BitLocker enable initiated on $Drive."
} else {
    Write-Host "BitLocker already enabled or in progress on $Drive. Ensuring a Recovery Password exists..."
    $info = Get-OrAddRecoveryPassword -MountPoint $Drive
}

Write-Host ""
Write-Host "Key Protectors on ${Drive}:"
(Get-BitLockerVolume -MountPoint $Drive).KeyProtector |
    Format-Table KeyProtectorType, KeyProtectorId -AutoSize

if ($info -and $info.NewlyCreated -and $info.RecoveryPassword) {
    $stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ssK'
    Write-Host ""
    Write-Host "=============================================================="
    Write-Host " NEW BITLOCKER RECOVERY KEY (save securely NOW):"
    Write-Host " $($info.RecoveryPassword)"
    Write-Host " ProtectorId: $($info.ProtectorId)"
    Write-Host " Timestamp  : $stamp"
    Write-Host "=============================================================="

    New-ItemProperty -Path $RegKey -Name 'RecoveryPassword' -Value $info.RecoveryPassword -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $RegKey -Name 'ProtectorId'      -Value $info.ProtectorId      -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $RegKey -Name 'Timestamp'        -Value $stamp                 -PropertyType String -Force | Out-Null
}