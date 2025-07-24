$ErrorActionPreference='Continue'; 
$skip='Public','Default','Default User','All Users'; 
$results=@(); 
Get-ChildItem C:\Users -Directory |
  Where-Object { $skip -notcontains $_.Name } |
  ForEach-Object {
    $nt = "$($_.FullName)\NTUSER.DAT"
    if (-not (Test-Path $nt)) { return }
    try { $sid = (Get-Acl $_.FullName).Owner.Split('\')[-1] } catch { return }
    $hive = "TempHive_$sid"
    reg.exe load "HKLM\$hive" $nt 2>$null
    $key = "HKLM:\$hive\Network"
    if (Test-Path $key) {
      Get-ChildItem $key | ForEach-Object {
        $drv = $_.PSChildName
        $rp  = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).RemotePath
        $results += [PSCustomObject]@{ User=$sid; Drive=$drv; Path=$rp }
      }
    }
    reg.exe unload "HKLM\$hive" 2>$null
  }

if ($results.Count) {
  $results |
    Sort-Object User,Drive |
    ForEach-Object { Write-Output "$($_.User) : $($_.Drive) => $($_.Path)" }
} else {
  Write-Output "No mapped drives found for any user."
}