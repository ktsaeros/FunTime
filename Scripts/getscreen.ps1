if(-not (Get-PSDrive HKU -ea 0)){New-PSDrive HKU Registry HKEY_USERS|Out-Null}; Get-ChildItem HKU:\ |
? { $_.Name -match 'HKEY_USERS\\S-1-5-21-.*(?!\\Classes$)' } |
%{
  $sid = $_.PSChildName
  $user = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid" -ea 0).ProfileImagePath
  $user = if($user){ Split-Path $user -Leaf } else { $sid }
  $p = Get-ItemProperty "Registry::$($_.Name)\Control Panel\Desktop" -ea 0
  $active = "$($p.ScreenSaveActive)"
  $to = [int]($p.ScreenSaveTimeOut | ForEach-Object {$_})
  $timeout = if(-not $p){'N/A'} elseif($active -ne '1' -or $to -eq 0){'Disabled'} elseif($to -ge 60 -and ($to%60 -eq 0)){"$($to/60) min"} elseif($to -ge 60){"$([math]::Round($to/60)) min"} else {"$to sec"}
  [pscustomobject]@{
    User        = $user
    ScreenSaver = if(-not $p){'N/A'} else $active
    Timeout     = $timeout
    Executable  = if(-not $p){'N/A'} else $p.'SCRNSAVE.EXE'
    Hive        = $_.Name
  }
} | Format-Table -AutoSize