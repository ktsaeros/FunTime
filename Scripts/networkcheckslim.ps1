param(
  [datetime]$Start = (Get-Date).AddDays(-14).Date,
  [datetime]$End   = (Get-Date),
  [string]$CsvOut  = "C:\ProgramData\Aeros\net_recovery_report.csv",
  [int]$MinDurationMinutes = 5,
  [int]$MinNetlogonFailsForBlip = 2
)

# Create output dir
New-Item -ItemType Directory -Force -Path (Split-Path $CsvOut) | Out-Null

# --- Event ID sets (from our investigation) ---
$idsNet = @{
  LinkDown   = @(27,32,4202,129)                 # NDIS/Tcpip/e1* "media/link down", resets
  LinkUp     = @(4201)                           # NDIS/Tcpip/e1* "link up"
  DHCP       = @(1001,1002)                      # DHCP client warnings/errors
  DNSFail    = @(1014)                           # DNS name resolution timeout
  NetlogonOK = @(5783)                           # Session setup to DC success
  NetlogonNo = @(5719)                           # Could not set up secure session to DC
}
$idsGpoOK = @(5308,5310,5312,5313,5320,5116,5126,5216,5257,4004,4005) # GPO contact/refresh markers

# Providers of interest
$provSystem = 'NETLOGON','NDIS','Tcpip','Dhcp','e1rexpress','e2rexpress','e3rexpress'
$provGpo    = 'Microsoft-Windows-GroupPolicy'
$provDNS    = 'Microsoft-Windows-DNS-Client'
$provNla    = 'Microsoft-Windows-NlaSvc','Microsoft-Windows-NetworkProfile'

# Agent/service context (adds color only)
$agentRegex = 'CyberCNS|Take Control|ScreenConnect|ConnectWise.*Control'

# --- Collect events ---
$ev = @()

# System: core networking + NETLOGON
$ev += Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$Start; EndTime=$End} -ErrorAction SilentlyContinue |
  Where-Object {
    $_.ProviderName -in $provSystem -or
    $_.Id -in ($idsNet.LinkDown + $idsNet.LinkUp + $idsNet.DHCP + $idsNet.DNSFail + $idsNet.NetlogonOK + $idsNet.NetlogonNo)
  } |
  Select-Object TimeCreated, LogName, Id, ProviderName, Message

# Group Policy (OK signals when DC reachable)
$ev += Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-GroupPolicy/Operational'; StartTime=$Start; EndTime=$End} -ErrorAction SilentlyContinue |
  Where-Object { $_.Id -in $idsGpoOK } |
  Select-Object TimeCreated, LogName, Id, ProviderName, Message

# DNS Client op log warnings/errors
$ev += Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-DNS-Client/Operational'; StartTime=$Start; EndTime=$End} -ErrorAction SilentlyContinue |
  Where-Object { $_.Id -in $idsNet.DNSFail -or $_.LevelDisplayName -match 'Warning|Error' } |
  Select-Object TimeCreated, LogName, Id, ProviderName, Message

# NLA/NCSI state hints (optional context)
$ev += Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-NlaSvc/Operational'; StartTime=$Start; EndTime=$End} -ErrorAction SilentlyContinue |
  Select-Object TimeCreated, LogName, Id, ProviderName, Message

# Service Control Manager (agent flaps)
$scm = Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$Start; EndTime=$End; ProviderName='Service Control Manager'} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match $agentRegex } |
  Select-Object TimeCreated, LogName, Id, ProviderName, Message
$ev += $scm

# Normalize + tag events
$short = {
  ($_ -replace '\r?\n',' ' -replace '\s+',' ').Trim()
}
$tagEvents = foreach($e in $ev){
  $type = switch ($true) {
    {$e.ProviderName -eq 'NETLOGON' -and $e.Id -in $idsNet.NetlogonNo} { 'NETLOGON_FAIL'; break }
    {$e.ProviderName -eq 'NETLOGON' -and $e.Id -in $idsNet.NetlogonOK} { 'NETLOGON_OK'; break }
    {$e.Id -in $idsNet.LinkDown}                                       { 'LINK_DOWN'; break }
    {$e.Id -in $idsNet.LinkUp}                                         { 'LINK_UP'; break }
    {$e.Id -in $idsNet.DNSFail}                                        { 'DNS_FAIL'; break }
    {$e.Id -in $idsNet.DHCP}                                           { 'DHCP_ISSUE'; break }
    {$e.LogName -like 'Microsoft-Windows-GroupPolicy/Operational' -and $e.Id -in $idsGpoOK} { 'GPO_OK'; break }
    {$e.ProviderName -eq 'Service Control Manager' -and $e.Message -match $agentRegex}      { 'AGENT_EVENT'; break }
    default { 'OTHER' }
  }
  [pscustomobject]@{
    Time        = $e.TimeCreated
    Source      = $e.ProviderName
    Log         = $e.LogName
    EventId     = $e.Id
    Type        = $type
    Message     = (& $short $e.Message)
  }
}

$timeline = $tagEvents | Sort-Object Time

# --- Build loss/recovery intervals (simple heuristic) ---
# Loss triggers: NETLOGON_FAIL or LINK_DOWN or burst of DNS/DHCP (>=3 within 10 min)
# Recovery triggers: NETLOGON_OK or GPO_OK or LINK_UP
function InBurst([datetime]$t){
  $winStart = $t.AddMinutes(-5)
  $winEnd   = $t.AddMinutes(5)
  ($timeline | Where-Object {
    $_.Time -ge $winStart -and $_.Time -le $winEnd -and $_.Type -in 'DNS_FAIL','DHCP_ISSUE'
  }).Count -ge 3
}

$intervals = New-Object System.Collections.Generic.List[object]
$state = 'OK'
$curStart = $null
$curFirst = $null

foreach($evn in $timeline){
  $isLoss =
    ($evn.Type -in 'NETLOGON_FAIL','LINK_DOWN') -or
    ($evn.Type -in 'DNS_FAIL','DHCP_ISSUE' -and (InBurst $evn.Time))

  $isRecovery =
    ($evn.Type -in 'NETLOGON_OK','GPO_OK','LINK_UP')

  if($state -eq 'OK' -and $isLoss){
    $state   = 'LOSS'
    $curStart = $evn.Time
    $curFirst = $evn
    continue
  }

  if($state -eq 'LOSS' -and $isRecovery){
    # Close interval
    $inRange = $timeline | Where-Object { $_.Time -ge $curStart -and $_.Time -le $evn.Time }
    $counts = @{
      NETLOGON_FAIL = ($inRange | Where-Object Type -eq 'NETLOGON_FAIL').Count
      LINK_DOWN     = ($inRange | Where-Object Type -eq 'LINK_DOWN').Count
      DNS_FAIL      = ($inRange | Where-Object Type -eq 'DNS_FAIL').Count
      DHCP_ISSUE    = ($inRange | Where-Object Type -eq 'DHCP_ISSUE').Count
      AGENT_EVENT   = ($inRange | Where-Object Type -eq 'AGENT_EVENT').Count
    }
    $intervals.Add([pscustomobject]@{
      Start            = $curStart
      End              = $evn.Time
      DurationMinutes  = [math]::Round((New-TimeSpan -Start $curStart -End $evn.Time).TotalMinutes,1)
      FirstIndicator   = "$($curFirst.Type) [$($curFirst.Source) $($curFirst.EventId)]"
      RecoveryMarker   = "$($evn.Type) [$($evn.Source) $($evn.EventId)]"
      NETLOGON_FAIL    = $counts.NETLOGON_FAIL
      LINK_DOWN        = $counts.LINK_DOWN
      DNS_FAIL         = $counts.DNS_FAIL
      DHCP_ISSUE       = $counts.DHCP_ISSUE
      AGENT_EVENTS     = $counts.AGENT_EVENT
    })
    $state   = 'OK'
    $curStart = $null
    $curFirst = $null
  }
}

# If we ended still in LOSS, leave an open interval to End
if($state -eq 'LOSS' -and $curStart){
  $inRange = $timeline | Where-Object { $_.Time -ge $curStart -and $_.Time -le $End }
  $counts = @{
    NETLOGON_FAIL = ($inRange | Where-Object Type -eq 'NETLOGON_FAIL').Count
    LINK_DOWN     = ($inRange | Where-Object Type -eq 'LINK_DOWN').Count
    DNS_FAIL      = ($inRange | Where-Object Type -eq 'DNS_FAIL').Count
    DHCP_ISSUE    = ($inRange | Where-Object Type -eq 'DHCP_ISSUE').Count
    AGENT_EVENT   = ($inRange | Where-Object Type -eq 'AGENT_EVENT').Count
  }
  $intervals.Add([pscustomobject]@{
    Start            = $curStart
    End              = $End
    DurationMinutes  = [math]::Round((New-TimeSpan -Start $curStart -End $End).TotalMinutes,1)
    FirstIndicator   = "$($curFirst.Type) [$($curFirst.Source) $($curFirst.EventId)]"
    RecoveryMarker   = "(open)"
    NETLOGON_FAIL    = $counts.NETLOGON_FAIL
    LINK_DOWN        = $counts.LINK_DOWN
    DNS_FAIL         = $counts.DNS_FAIL
    DHCP_ISSUE       = $counts.DHCP_ISSUE
    AGENT_EVENTS     = $counts.AGENT_EVENT
  })
}

# --- Noise filters ---
# Keep intervals that are EITHER long enough OR multi-symptom.
$intervalsFiltered = $intervals | Where-Object {
  ($_.DurationMinutes -ge $MinDurationMinutes) -or
  ($_.LINK_DOWN -gt 0 -or $_.DNS_FAIL -gt 0 -or $_.DHCP_ISSUE -gt 0) -or
  ($_.NETLOGON_FAIL -ge $MinNetlogonFailsForBlip)
}

# --- Output ---
"`n=== Network Loss/Recovery Intervals (filtered) ==="
$intervalsFiltered | Sort-Object Start | Format-Table -Auto

"`n=== Network Loss/Recovery Intervals (raw) ==="
$intervals | Sort-Object Start | Format-Table -Auto

"`n=== Key Event Timeline (filtered intervals only, trimmed) ==="
$filteredRanges = @()
foreach($r in ($intervalsFiltered | Sort-Object Start)){
  $filteredRanges += @{ Start = $r.Start; End = $r.End }
}
$timeline |
  Where-Object {
    $_.Type -in 'NETLOGON_FAIL','NETLOGON_OK','LINK_DOWN','LINK_UP','DNS_FAIL','DHCP_ISSUE','GPO_OK','AGENT_EVENT' -and
    ($filteredRanges.Count -eq 0 -or ($filteredRanges | Where-Object { $_.Start -le $_this.Time -and $_this.Time -le $_.End }))
  } |
  Select-Object Time, Type, Source, EventId, @{n='Msg';e={($_.Message -replace '.{200}$','...').Substring(0,[math]::Min(200, $_.Message.Length))}} |
  Sort-Object Time |
  Format-Table -Auto

# Save CSVs
$intervals | Sort-Object Start | Export-Csv -NoTypeInformation -UseCulture -Path $CsvOut
$filteredPath = [System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName($CsvOut), ([System.IO.Path]::GetFileNameWithoutExtension($CsvOut) + "_filtered.csv"))
$intervalsFiltered | Sort-Object Start | Export-Csv -NoTypeInformation -UseCulture -Path $filteredPath

"CSV written: $CsvOut"
"CSV (filtered) written: $filteredPath"
