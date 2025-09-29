# List screensaver settings for all loaded user hives (HKU\S-1-5-21-...)
if (-not (Get-PSDrive HKU -ea 0)) { New-PSDrive HKU Registry HKEY_USERS | Out-Null }

Get-ChildItem HKU:\ -ea 0 |
  Where-Object { $_.Name -match 'HKEY_USERS\\S-1-5-21-.*' -and $_.Name -notmatch '\\Classes$' } |
  ForEach-Object {
    $sid  = $_.PSChildName
    $prof = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid" -ea 0
    $user = $( if ($prof -and $prof.ProfileImagePath) { Split-Path $prof.ProfileImagePath -Leaf } else { $sid } )

    $p = Get-ItemProperty "Registry::$($_.Name)\Control Panel\Desktop" -ea 0
    $active = if ($p) { "$($p.ScreenSaveActive)" } else { $null }
    $to     = if ($p) { [int]($p.ScreenSaveTimeOut | ForEach-Object { $_ }) } else { $null }
    $exe    = if ($p) { $p.'SCRNSAVE.EXE' } else { $null }

    $timeout = if (-not $p) {
      'N/A'
    } elseif ($active -ne '1' -or $to -eq 0) {
      'Disabled'
    } elseif ($to -ge 60 -and ($to % 60 -eq 0)) {
      "{0} min" -f ($to/60)
    } elseif ($to -ge 60) {
      "{0} min" -f [math]::Round($to/60)
    } else {
      "{0} sec" -f $to
    }

    [pscustomobject]@{
      User        = $user
      ScreenSaver = $( if (-not $p) { 'N/A' } else { $active } )
      Timeout     = $timeout
      Executable  = $( if (-not $p) { 'N/A' } else { $exe } )
      Hive        = $_.Name
    }
  } | Format-Table -AutoSize