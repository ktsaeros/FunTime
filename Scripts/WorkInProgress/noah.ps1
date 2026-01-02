<#
Purpose:
- Preserve original AC settings
- If battery present: Sleep after 30 minutes on DC
- Sleep on lid close (both AC and DC)
- Apply cleanly to the active power scheme

Run as Administrator (or SYSTEM in N-able).
#>

$ErrorActionPreference = 'Stop'

# --- Original AC settings ---
powercfg /change monitor-timeout-ac 30
powercfg /change disk-timeout-ac 0
powercfg /change standby-timeout-ac 0
#powercfg /change hibernate-timeout-ac 0
powercfg /hibernate off

# --- Detect battery / laptop chassis ---
$battery     = Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue
$chassisType = (Get-CimInstance -ClassName Win32_SystemEnclosure -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty ChassisTypes)
$isLaptop    = $false
if ($chassisType) {
    $isLaptop = ($chassisType -contains 9  -or  # Laptop
                 $chassisType -contains 10 -or  # Notebook
                 $chassisType -contains 14 -or  # Sub-Notebook
                 $chassisType -contains 18 -or  # Expansion Chassis (some convertibles)
                 $chassisType -contains 21)     # Peripheral Chassis (seen on some laptops)
}

# --- If battery present: set DC timeouts (sleep after 30 min) ---
if ($battery) {
    powercfg /change monitor-timeout-dc 10
    powercfg /change disk-timeout-dc 0
    powercfg /change standby-timeout-dc 30    # <-- Sleep after 30 minutes on battery
    powercfg /change hibernate-timeout-dc 0   # Never auto-hibernate on DC
}

# --- Always set lid close action to Sleep (AC & DC) on laptops ---
if ($isLaptop) {
    # GUIDs for "Power buttons and lid" subgroup and "Lid close action"
    $SUB_BUTTONS = '4f971e89-eebd-4455-a8de-9e59040e7347' # Power buttons and lid
    $LID_ACTION  = '5ca83367-6e45-459f-a27b-476b1d01c936' # Lid close action

    # Values: 0=Do nothing, 1=Sleep, 2=Hibernate, 3=Shut down
    $SLEEP = 1

    # Set on the current scheme
    powercfg -setacvalueindex SCHEME_CURRENT $SUB_BUTTONS $LID_ACTION $SLEEP | Out-Null
    powercfg -setdcvalueindex SCHEME_CURRENT $SUB_BUTTONS $LID_ACTION $SLEEP | Out-Null
}

# Re-apply active scheme so changes take effect immediately
$active = (powercfg /getactivescheme) -replace '.*GUID:\s*([0-9a-fA-F-]+).*','$1'
if ($active) { powercfg -setactive $active | Out-Null }

Write-Host "Power settings applied:
- AC: monitor=30m, disk=Never, sleep=Never, hibernate=Off
- DC: monitor=10m, disk=Never, sleep=30m (if battery present)
- Lid close: Sleep on AC & DC (laptops)
" -ForegroundColor Green