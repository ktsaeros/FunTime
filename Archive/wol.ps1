# WOL-Report-Only.ps1
# Reports Wake-on-LAN related settings and prints the commands to change them (does not make changes)

function Get-AdvPropSafe {
    param($Name)
    try {
        Get-NetAdapterAdvancedProperty -Name $Name -ErrorAction Stop |
            Select-Object Name, DisplayName, DisplayValue, RegistryKeyword
    } catch {
        @()
    }
}

function Get-PmSafe {
    param($Name)
    try {
        Get-NetAdapterPowerManagement -Name $Name -ErrorAction Stop |
            Select-Object Name, AllowComputerToTurnOffDevice, AllowWakeFromAny, WakeOnMagicPacket, WakeOnPattern
    } catch {
        $null
    }
}

Write-Host "Enumerating network adapters..."
$adapters = Get-NetAdapter -Physical | Where-Object { $_.Status -ne 'Disabled' }

foreach ($nic in $adapters) {
    $pm  = Get-PmSafe -Name $nic.Name
    $adv = Get-AdvPropSafe -Name $nic.Name

    Write-Host "`n=== Adapter: $($nic.Name) ($($nic.InterfaceDescription)) ==="
    Write-Host "MAC Address: $($nic.MacAddress)"
    Write-Host "Power Mgmt - WakeOnMagicPacket: $($pm?.WakeOnMagicPacket)"
    Write-Host "Power Mgmt - WakeOnPattern:     $($pm?.WakeOnPattern)"
    Write-Host "Power Mgmt - AllowWakeFromAny:  $($pm?.AllowWakeFromAny)"

    $magicAdv = $adv | Where-Object {
        $_.DisplayName -like '*Magic*' -or $_.RegistryKeyword -like '*Magic*'
    }

    if ($magicAdv) {
        foreach ($prop in $magicAdv) {
            Write-Host "Advanced: $($prop.DisplayName) = $($prop.DisplayValue)"
        }
    }

    # === Print out commands to enable WOL ===
    Write-Host "`n--- Commands to enable Wake on Magic Packet ---"
    Write-Host "Set-NetAdapterPowerManagement -Name '$($nic.Name)' -WakeOnMagicPacket Enabled"
    foreach ($prop in $magicAdv) {
        Write-Host "Set-NetAdapterAdvancedProperty -Name '$($nic.Name)' -DisplayName '$($prop.DisplayName)' -DisplayValue 'Enabled'"
    }
    Write-Host "powercfg -deviceenablewake `"$($nic.Name)`""
}

Write-Host "`n=== OS Wake Lists ==="
Write-Host "Wake-armed devices:"
powercfg -devicequery wake_armed
Write-Host "`nWake-programmable devices:"
powercfg -devicequery wake_programmable
Write-Host "`nSleep states:"
powercfg -a