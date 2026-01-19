<#
Shows Power button, Sleep button, and Lid close actions (AC/DC) for the ACTIVE power plan.
- Prefers registry (matches Control Panel UI), falls back to powercfg /q.
- Detects policy overrides if present.
Windows PowerShell 5.1 compatible.
#>

$ActionMap = @{
  0 = 'Do nothing'
  1 = 'Sleep'
  2 = 'Hibernate'
  3 = 'Shut down'
  4 = 'Turn off display'
}

function Resolve-Action($Code) {
   if ($null -eq $Code -or $Code -eq '') { return $ActionMap[0] }  # was: 'N/A'
  $int = [int]$Code
  if ($ActionMap.ContainsKey($int)) { return $ActionMap[$int] }
  "Unknown ($Code)"
}

function Get-ActiveSchemeGuid {
  $line = powercfg /getactivescheme 2>$null
  if ($line -match 'GUID:\s*([0-9a-fA-F-]+)') { return $matches[1] }
  throw "Could not read active power scheme GUID."
}

# Subgroup + setting GUIDs
$SUB = '4f971e89-eebd-4455-a8de-9e59040e7347'  # Power buttons and lid
$SET = [ordered] @{
  'Power button' = '7648efa3-dd9c-4e3e-b566-50f929386280'  # PBUTTONACTION
  'Sleep button' = '96996bc0-ad50-47ec-923b-6f41874dd9eb'  # SBUTTONACTION
  'Lid close'    = '5ca83367-6e45-459f-a27b-476b1d01c936'  # LIDACTION
}

function Get-SettingValues([string]$Scheme,[string]$Sub,[string]$Setting) {
  # 1) Policy override?
  $pol = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\$Sub\$Setting"
  $acPol = (Get-ItemProperty -Path $pol -Name ACSettingIndex -ErrorAction SilentlyContinue).ACSettingIndex
  $dcPol = (Get-ItemProperty -Path $pol -Name DCSettingIndex -ErrorAction SilentlyContinue).DCSettingIndex
  if ($acPol -ne $null -or $dcPol -ne $null) {
    return [pscustomobject]@{ AC = $acPol; DC = $dcPol; Source = 'Policy' }
  }

  # 2) Registry (matches Control Panel "Choose what the power buttons do")
  $reg = "HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\$Scheme\$Sub\$Setting"
  $acReg = (Get-ItemProperty -Path $reg -Name ACSettingIndex -ErrorAction SilentlyContinue).ACSettingIndex
  $dcReg = (Get-ItemProperty -Path $reg -Name DCSettingIndex -ErrorAction SilentlyContinue).DCSettingIndex
  if ($acReg -ne $null -or $dcReg -ne $null) {
    return [pscustomobject]@{ AC = $acReg; DC = $dcReg; Source = 'Registry' }
  }

  # 3) Fallback to parsing powercfg /q
  $ac = $null; $dc = $null
  foreach ($line in (powercfg /q $Scheme $Sub $Setting 2>$null)) {
    if ($line -match 'Current AC Power Setting Index:\s*0x([0-9A-Fa-f]+)') { $ac = [Convert]::ToInt32($matches[1],16) }
    if ($line -match 'Current DC Power Setting Index:\s*0x([0-9A-Fa-f]+)') { $dc = [Convert]::ToInt32($matches[1],16) }
  }
  [pscustomobject]@{ AC = $ac; DC = $dc; Source = 'PowerCfg' }
}

$scheme = Get-ActiveSchemeGuid

$rows = foreach ($kv in $SET.GetEnumerator()) {
  $v = Get-SettingValues -Scheme $scheme -Sub $SUB -Setting $kv.Value
  [pscustomobject]@{
  Setting   = $kv.Key
  OnBattery = Resolve-Action $v.DC
  PluggedIn = Resolve-Action $v.AC
  Source    = $v.Source
}
}

$rows | Format-Table Setting,OnBattery,PluggedIn,Source -AutoSize