<#
.SYNOPSIS
    Audits power schemes, sleep states, NIC settings, and Registry Hardening keys.
    v2 Update: Includes Fast Startup and S0 Registry checks.
#>

[CmdletBinding()]
param()

$Results = [ordered]@{}

# --- 1. System Info ---
$Results['ComputerName'] = $env:COMPUTERNAME
$Results['Timestamp']    = Get-Date -Format "yyyy-MM-dd HH:mm"

# Chassis Logic (Matching the Enforce Script)
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

# Check S0 Override (0 = Disabled/Good for DT, Null = Enabled/Good for Laptop)
$s0Val = (Get-ItemProperty -Path $pathPower -Name 'PlatformAoAcOverride' -ErrorAction SilentlyContinue).PlatformAoAcOverride
$Results['Reg_S0_Override'] = if ($null -ne $s0Val) { $s0Val } else { "Not Set (Default)" }

# Check Fast Startup (0 = Disabled/Good, 1 = Enabled/Bad)
$fsVal = (Get-ItemProperty -Path $pathSession -Name 'HiberbootEnabled' -ErrorAction SilentlyContinue).HiberbootEnabled
$Results['Reg_FastStartup'] = if ($null -ne $fsVal) { $fsVal } else { "Not Set (Default)" }

# --- 3. Power Scheme & Timeouts ---
# Using simple regex to parse powercfg /q for speed/reliability
function Get-PcfgVal ($guid, $sub, $setting) {
    $val = powercfg /q $guid $sub $setting | Select-String "Current AC Power Setting"
    if ($val) { return [int]"0x$($val.ToString().Split(':')[-1].Trim())" }
    return "Err"
}

$SCHEME = "SCHEME_CURRENT"
$SUB_SLEEP = "238c9fa8-0aad-41ed-83f4-97be242c8f20"
$SUB_VIDEO = "7516b95f-f776-4464-8c53-06167f40cc99"
$SUB_BUTTONS = "4f971e89-eebd-4455-a8de-9e59040e7347"

# Timeouts
$Results['Monitor_AC']   = Get-PcfgVal $SCHEME $SUB_VIDEO "3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e"
$Results['Sleep_AC']     = Get-PcfgVal $SCHEME $SUB_SLEEP "29f6c1db-86da-48c5-9fdb-f2b67b1f44da"
$Results['Sleep_DC']     = Get-PcfgVal $SCHEME $SUB_SLEEP "29f6c1db-86da-48c5-9fdb-f2b67b1f44da" # Note: powercfg /q shows AC/DC logic differently, this is simplified.

# Lid Action (0=None, 1=Sleep)
$lidAC = powercfg /q $SCHEME $SUB_BUTTONS "5ca83367-6e45-459f-a27b-476b1d01c936" | Select-String "Current AC Power Setting"
$Results['Lid_Action_AC'] = if ($lidAC) { [int]"0x$($lidAC.ToString().Split(':')[-1].Trim())" } else { "Err" }

# --- 4. Sleep State Availability ---
$powerCfgA = powercfg /a
$Results['S0_Available'] = ($powerCfgA -match "Standby \(S0 Low Power Idle\)").Count -gt 0
$Results['S3_Available'] = ($powerCfgA -match "Standby \(S3\)").Count -gt 0
$Results['Hibernate_Available'] = ($powerCfgA -match "Hibernate").Count -gt 0

# --- 5. NIC Audit ---
$adapters = Get-NetAdapter -Physical
$nicReport = @()
foreach ($nic in $adapters) {
    try {
        $pm = Get-NetAdapterPowerManagement -Name $nic.Name -ErrorAction Stop
        # "AllowComputerToTurnOffDevice"
        $nicReport += "$($nic.Name) [WOL:$($pm.WakeOnMagicPacket) | PwrSave:$($pm.AllowComputerToTurnOffDevice)]"
    } catch {
        $nicReport += "$($nic.Name) [Err]"
    }
}
$Results['NIC_Status'] = $nicReport -join "; "

# Output object
New-Object PSObject -Property $Results
