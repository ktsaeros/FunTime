<#
.SYNOPSIS
    Audits power schemes, sleep states, NIC settings, and Registry Hardening keys.
    v3 Update: Fixed GUID resolution for 24H2 / Modern Standby.
#>

[CmdletBinding()]
param()

$Results = [ordered]@{}

# --- 1. System Info ---
$Results['ComputerName'] = $env:COMPUTERNAME
$Results['Timestamp']    = Get-Date -Format "yyyy-MM-dd HH:mm"

# Chassis Logic
$chassis = Get-CimInstance -ClassName Win32_SystemEnclosure
$battery = Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch 'UPS|Uninterruptible' }
$laptopTypes = @(8, 9, 10, 11, 12, 14, 18, 21, 30, 31, 32)
if (($chassis.ChassisTypes | Where-Object { $_ -in $laptopTypes }) -or $battery) { 
    $Results['Chassis'] = "Laptop" 
} else { 
    $Results['Chassis'] = "Desktop" 
}

# --- 2. Registry Hardening Checks ---
$pathPower = 'HKLM:\SYSTEM\CurrentControlSet\Control\Power'
$pathSession = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power'
$s0Val = (Get-ItemProperty -Path $pathPower -Name 'PlatformAoAcOverride' -ErrorAction SilentlyContinue).PlatformAoAcOverride
$Results['Reg_S0_Override'] = if ($null -ne $s0Val) { $s0Val } else { "Not Set (Default)" }
$fsVal = (Get-ItemProperty -Path $pathSession -Name 'HiberbootEnabled' -ErrorAction SilentlyContinue).HiberbootEnabled
$Results['Reg_FastStartup'] = if ($null -ne $fsVal) { $fsVal } else { "Not Set (Default)" }

# --- 3. Power Scheme & Timeouts ---
# Get Actual Active Scheme GUID
$SCHEME = (powercfg /getactivescheme).Split()[3]

function Get-PcfgVal ($guid, $sub, $setting) {
    $val = powercfg /q $guid $sub $setting | Select-String "Current AC Power Setting"
    if ($val) { return [int]"0x$($val.ToString().Split(':')[-1].Trim())" }
    return "Err"
}

$SUB_SLEEP = "238c9fa8-0aad-41ed-83f4-97be242c8f20"
$SUB_VIDEO = "7516b95f-f776-4464-8c53-06167f40cc99"
$SUB_PCI   = "501a4d13-42af-4429-9fd1-a8218c268e20"
$SUB_DISK  = "0012ee47-9041-4b5d-9b77-535fba8b1442"
$SUB_USB   = "2a737441-1930-4402-8d77-b2bebba308a3"

# Timeouts & Settings
$Results['Monitor_AC']      = Get-PcfgVal $SCHEME $SUB_VIDEO "3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e"
$Results['Sleep_AC']        = Get-PcfgVal $SCHEME $SUB_SLEEP "29f6c1db-86da-48c5-9fdb-f2b67b1f44da"
$Results['PCIe_Link_State'] = Get-PcfgVal $SCHEME $SUB_PCI   "ee12f906-25ea-4e32-9679-880e263438db"
$Results['Disk_Timeout']    = Get-PcfgVal $SCHEME $SUB_DISK  "6738e2c4-e8a5-459e-b6a6-0b92ed98b3aa"
$Results['USB_Sel_Suspend'] = Get-PcfgVal $SCHEME $SUB_USB   "48e6b7a6-50f5-4782-a5d4-53bb8f07e226"

# Interpret Results
$Results['PCIe_Link_State'] = switch ($Results['PCIe_Link_State']) { 0 {'Off (Good)'} 1 {'Moderate'} 2 {'Max Savings (Risk)'} default {'Err'} }
$Results['USB_Sel_Suspend'] = switch ($Results['USB_Sel_Suspend']) { 0 {'Disabled (Good)'} 1 {'Enabled (Risk)'} default {'Err'} }

# --- 4. Sleep Availability ---
$powerCfgA = powercfg /a
$Results['S0_Available'] = ($powerCfgA -match "Standby \(S0 Low Power Idle\)").Count -gt 0
$Results['S3_Available'] = ($powerCfgA -match "Standby \(S3\)").Count -gt 0

# --- 5. NIC Audit ---
$adapters = Get-NetAdapter -Physical -ErrorAction SilentlyContinue
$nicReport = @()
foreach ($nic in $adapters) {
    try {
        $pm = Get-NetAdapterPowerManagement -Name $nic.Name -ErrorAction Stop
        $nicReport += "$($nic.Name) [WOL:$($pm.WakeOnMagicPacket) | PwrSave:$($pm.AllowComputerToTurnOffDevice)]"
    } catch { $nicReport += "$($nic.Name) [Err]" }
}
$Results['NIC_Status'] = $nicReport -join "; "

New-Object PSObject -Property $Results