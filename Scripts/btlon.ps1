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
        # Try to read the password if the object model happens to expose it
        $pwExisting = ($existing | Select-Object -First 1).RecoveryPassword
        return [pscustomobject]@{
            NewlyCreated     = $false
            RecoveryPassword = $pwExisting
            ProtectorId      = $existing[0].KeyProtectorId
        }
    }

    # Create the protector
    $added = Add-BitLockerKeyProtector -MountPoint $MountPoint -RecoveryPasswordProtector -WarningAction SilentlyContinue

    # Capture path A: direct from Add-* output
    $pw  = $added.RecoveryPassword
    $ProtId = if ($added.KeyProtector) { $added.KeyProtector.KeyProtectorId } else { $null }

    # Capture path B: sometimes the object model has it after creation
    if (-not $pw) {
        $v2 = Get-BitLockerVolume -MountPoint $MountPoint
        $kp = $v2.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' } | Select-Object -First 1
        if ($kp) {
            if (-not $ProtId) { $ProtId = $kp.KeyProtectorId }
            if ($kp.RecoveryPassword) { $pw = $kp.RecoveryPassword }
        }
    }

    # Capture path C (fallback): scrape manage-bde for any 48-digit pattern
    if (-not $pw) {
        $txt = (manage-bde -protectors -get $MountPoint | Out-String)
        $pw  = [regex]::Matches($txt, '([0-9]{6}-){7}[0-9]{6}') | Select-Object -First 1 -ExpandProperty Value
    }

    # Do NOT throw if we still couldn't capture it — protector exists and we can fetch later
    [pscustomobject]@{
        NewlyCreated     = $true
        RecoveryPassword = $pw      # may be $null; we’ll still proceed
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
} else {
    Write-Host "Recovery Password was created but not captured to stdout; you can query it via manage-bde or the BitLocker object model."
}