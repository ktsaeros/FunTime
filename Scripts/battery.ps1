<# 
.SYNOPSIS
  Lists system batteries (laptop + HID/USB UPS) with useful status fields.

.NOTES
  - Works on Windows 10/11.
  - UPS devices that expose a "HID UPS Battery" will show up via Win32_Battery.
  - Requires no admin privileges.
#>

param(
  [switch]$DisableGenericHIDUPS,   # Optional: disable HID UPS Battery (admin)
  [switch]$EnableGenericHIDUPS,    # Optional: re-enable HID UPS Battery (admin)
  [switch]$AuditOnly               # Show what would happen, don't change devices
)

function Test-IsAdmin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Get-ChassisIsDesktop {
  # Avoid disabling on laptops/convertibles
  try {
    $types = (Get-CimInstance Win32_SystemEnclosure).ChassisTypes
    # Common desktop-ish codes: 3=Desktop, 4=Low-profile, 5=Pizza Box, 6=Mini Tower, 7=Tower, 13=All-in-One, 15=Space-Saving, 23=Sub-Chassis
    # Common portable-ish codes: 8=Portable, 9=Laptop, 10=Notebook, 14=Sub-Notebook, 30=Convertible, 31=Detachable
    $portable = 8,9,10,14,30,31
    if ($types) { return -not ($types | Where-Object { $_ -in $portable }) }
  } catch {}
  $true # default to desktop if unknown
}

# Collect PnP devices (Battery + HIDClass + anything that mentions UPS-ish names)
$pnp = Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue |
       Select-Object InstanceId, FriendlyName, Class, Status

# Flag pattern
$upsPattern = 'UPS|Uninterruptible|Power Conversion|APC|CyberPower|Tripp|Eaton|Vertiv|Liebert|HID UPS'

# Identify the generic HID UPS Battery (the one we might disable on CPCs)
$genericHidUps = $pnp | Where-Object { $_.Class -eq 'Battery' -and $_.FriendlyName -eq 'HID UPS Battery' }

# Show what’s present (this matches your troubleshooting filter, but richer)
$upsView = $pnp |
  Where-Object {
    $_.FriendlyName -match $upsPattern -or
    ($_.Class -eq 'Battery' -and $_.FriendlyName -match 'Battery|UPS')
  } |
  Select-Object @{n='GenericHIDBattery';e={ $_.FriendlyName -eq 'HID UPS Battery' }},
                Status, Class, FriendlyName, InstanceId

if ($upsView) {
  $upsView | Sort-Object -Property @{Expression='GenericHIDBattery';Descending=$true}, Class, FriendlyName |
    Format-Table -Auto
} else {
  Write-Host "No UPS-like PnP devices detected."
}

# Optional control: Disable/Enable the generic HID UPS Battery
if ($DisableGenericHIDUPS -or $EnableGenericHIDUPS) {
  if (-not (Test-IsAdmin)) { throw "Disabling/enabling devices requires an elevated PowerShell." }
  if (-not (Get-ChassisIsDesktop)) { throw "This looks like a portable chassis. Refusing to change battery devices." }
}

if ($DisableGenericHIDUPS) {
  if (-not $genericHidUps) {
    Write-Host "No 'HID UPS Battery' device found to disable."
  } else {
    foreach ($d in $genericHidUps) {
      Write-Host "Would disable: $($d.FriendlyName) [$($d.InstanceId)]"
      if (-not $AuditOnly) {
        Disable-PnpDevice -InstanceId $d.InstanceId -Confirm:$false -ErrorAction Stop
        Write-Host "Disabled: $($d.InstanceId)"
      }
    }
  }
}

if ($EnableGenericHIDUPS) {
  if (-not $genericHidUps) {
    # It might be present but disabled; query all (not just PresentOnly)
    $any = Get-PnpDevice -Class Battery -ErrorAction SilentlyContinue |
           Where-Object FriendlyName -eq 'HID UPS Battery'
    if ($any) { $genericHidUps = $any }
  }
  if (-not $genericHidUps) {
    Write-Host "'HID UPS Battery' not found to enable."
  } else {
    foreach ($d in $genericHidUps) {
      Write-Host "Would enable: $($d.FriendlyName) [$($d.InstanceId)]"
      if (-not $AuditOnly) {
        Enable-PnpDevice -InstanceId $d.InstanceId -Confirm:$false -ErrorAction Stop
        Write-Host "Enabled: $($d.InstanceId)"
      }
    }
  }
}


# Map common enums to friendly text
$BatteryStatusMap = @{
  1  = "Discharging"
  2  = "AC (not charging)"
  3  = "Fully Charged"
  4  = "Low"
  5  = "Critical"
  6  = "Charging"
  7  = "Charging (High)"
  8  = "Charging (Low)"
  9  = "Charging (Critical)"
  10 = "Undefined"
  11 = "Partially Charged"
}
$ChemistryMap = @{
  1="Other";2="Unknown";3="Lead Acid";4="NiCd";5="NiMH";6="Li-ion";7="Zinc-air";8="Li-Polymer"
}

function Get-SystemACState {
  try {
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop | Out-Null
    $ps = [System.Windows.Forms.SystemInformation]::PowerStatus
    [pscustomobject]@{
      OnACPower = ($ps.PowerLineStatus -eq 'Online')
      BatteryPercent = [math]::Round($ps.BatteryLifePercent * 100, 0)
      BatteryLifeRemainingSec = $ps.BatteryLifeRemaining
    }
  } catch {
    # Fallback using Win32_Battery (less reliable for AC state on desktops)
    $b = Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue
    [pscustomobject]@{
      OnACPower = ($b.BatteryStatus -in 2,3,6,7,8,9,11)
      BatteryPercent = $b.EstimatedChargeRemaining
      BatteryLifeRemainingSec = ($b.EstimatedRunTime * 60)
    }
  }
}

function Get-PowerBatteries {
  # Primary source: Win32_Battery (covers laptop batteries and most HID UPS)
  $bats = Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue

  # Enrich with PnP hints to help distinguish UPS vs Laptop pack
  try {
    # Prefer Get-PnpDevice if available (newer systems)
    $pnp = Get-PnpDevice -Class Battery -ErrorAction Stop |
           Select-Object InstanceId, FriendlyName, Status
  } catch {
    # Fallback to Win32_PnPEntity
    $pnp = Get-CimInstance -ClassName Win32_PnPEntity -Filter "PNPClass='Battery'" -ErrorAction SilentlyContinue |
           Select-Object PNPDeviceID, Name, Status
    # Normalize names for later join
    $pnp = $pnp | ForEach-Object {
      [pscustomobject]@{
        InstanceId   = $_.PNPDeviceID
        FriendlyName = $_.Name
        Status       = $_.Status
      }
    }
  }

 # --- Replace your existing PnP discovery + UPS hints with this ---

# Grab PnP devices across classes (Battery & HIDClass) and look for UPS-ish names
$pnp = Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue |
       Select-Object InstanceId, FriendlyName, Class, Status

# Patterns that commonly identify UPS vendors/devices
$upsPattern = 'UPS|Uninterruptible|Power Conversion|APC|CyberPower|Tripp|Eaton|Vertiv|Liebert|HID UPS'

# Primary source: Win32_Battery (covers laptops and many HID UPSes)
$bats = Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue

$results = @()

foreach ($b in ($bats | Where-Object { $_ })) {
  $match = $null
  if ($b.PNPDeviceID) {
    $match = $pnp | Where-Object { $_.InstanceId -eq $b.PNPDeviceID }
    if (-not $match) {
      $tail = $b.PNPDeviceID.Split('\')[-1]
      $match = $pnp | Where-Object { $_.InstanceId -like "*$tail*" }
    }
  }
  $friendly = if ($match) { $match.FriendlyName } else { $b.Name }
  $isUPS = ($friendly -match $upsPattern) -or ($b.Name -match $upsPattern) -or ($b.Description -match $upsPattern)

  $results += [pscustomobject]@{
    Type                   = if ($isUPS) { "UPS" } else { "Laptop Battery" }
    Name                   = $friendly
    DeviceID               = $b.DeviceID
    PNPDeviceID            = $b.PNPDeviceID
    Chemistry              = @{1="Other";2="Unknown";3="Lead Acid";4="NiCd";5="NiMH";6="Li-ion";7="Zinc-air";8="Li-Polymer"}[[int]$b.Chemistry]
    DesignVoltage_mV       = $b.DesignVoltage
    EstimatedChargePercent = $b.EstimatedChargeRemaining
    EstimatedRunTime_min   = if ($b.EstimatedRunTime -ge 0) { $b.EstimatedRunTime } else { $null }
    BatteryStatus          = @{
      1="Discharging";2="AC (not charging)";3="Fully Charged";4="Low";5="Critical";6="Charging";7="Charging (High)";
      8="Charging (Low)";9="Charging (Critical)";10="Undefined";11="Partially Charged"
    }[[int]$b.BatteryStatus]
    Status                 = $b.Status
    TimeOnBattery_sec      = $b.TimeOnBattery
    ExpectedLife_min       = $b.ExpectedLife
    DesignCapacity_mWh     = $b.DesignCapacity
    FullChargeCapacity_mWh = $b.FullChargeCapacity
  }
}

# If Win32_Battery gave us nothing, surface UPS-looking PnP devices as hints (Battery + HIDClass)
if (-not $results) {
  $upsHints = $pnp | Where-Object {
    $_.FriendlyName -match $upsPattern -or ($_.Class -in 'Battery','HIDClass' -and $_.FriendlyName -match 'UPS|Battery')
  }

  foreach ($u in $upsHints) {
    $results += [pscustomobject]@{
      Type                   = "UPS (PnP hint)"
      Name                   = $u.FriendlyName
      DeviceID               = $null
      PNPDeviceID            = $u.InstanceId
      Chemistry              = $null
      DesignVoltage_mV       = $null
      EstimatedChargePercent = $null
      EstimatedRunTime_min   = $null
      BatteryStatus          = $null
      Status                 = $u.Status
      TimeOnBattery_sec      = $null
      ExpectedLife_min       = $null
      DesignCapacity_mWh     = $null
      FullChargeCapacity_mWh = $null
    }
  }
}

  $results
}

# ---------- Run & Display ----------
$ac = Get-SystemACState
$batteries = Get-PowerBatteries

Write-Host "AC Power: " -NoNewline
if ($ac.OnACPower) { Write-Host "Online" } else { Write-Host "On Battery" }

if ($ac.BatteryPercent -ne $null) {
  Write-Host ("System Battery %: {0}%" -f $ac.BatteryPercent)
}
if ($ac.BatteryLifeRemainingSec -gt 0) {
  $mins = [int]([math]::Round($ac.BatteryLifeRemainingSec / 60,0))
  Write-Host ("Estimated Remaining: {0} min" -f $mins)
}

if ($batteries) {
  $batteries | Sort-Object Type, Name | Format-Table Type, Name, EstimatedChargePercent, BatteryStatus, EstimatedRunTime_min, Chemistry, PNPDeviceID -AutoSize
} else {
  Write-Host "No batteries reported by Win32_Battery."
}