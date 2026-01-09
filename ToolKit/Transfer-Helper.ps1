<#
.SYNOPSIS
    Aeros Workgroup Transfer Helper (Toolbox Edition)
    Accepts parameters to handle permissions and transfers silently.
#>

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("Sender","Receiver","Status")]
    [string]$Mode,

    [string]$SourcePath,
    [string]$DestPath = "C:\Users\Public\Documents\Intuit\QuickBooks",
    
    [string]$RemoteHost,
    [string]$RemoteShare = "QuickBooks",
    [string]$RemoteFile,
    [string]$RemoteUser = "transfer"
)

# ASCII Headers (Safe for all RMMs)
function Show-Header {
    Write-Host "+-------------------------------------------------------+" -ForegroundColor Cyan
    Write-Host "|         AEROS WORKGROUP FILE TRANSFER WIZARD          |" -ForegroundColor Cyan
    Write-Host "+-------------------------------------------------------+" -ForegroundColor Cyan
}

if ($Mode -eq "Sender") {
    Show-Header
    Write-Host " [MODE: SENDER]" -ForegroundColor Yellow
    
    if (-not $SourcePath) { Write-Host " [!] Error: No SourcePath provided." -ForegroundColor Red; return }
    if (-not (Test-Path $SourcePath)) { Write-Host " [!] Source file not found: $SourcePath" -ForegroundColor Red; return }

    # 1. Ensure Dest Exists
    if (-not (Test-Path $DestPath)) {
        New-Item -Path $DestPath -ItemType Directory -Force | Out-Null
    }

    # 2. Move File
    $fileName = Split-Path $SourcePath -Leaf
    $finalPath = Join-Path $DestPath $fileName
    
    Write-Host " Moving: $fileName" -ForegroundColor Gray
    Move-Item -Path $SourcePath -Destination $DestPath -Force

    # 3. Fix Permissions
    Write-Host " Fixing Permissions..." -ForegroundColor Gray
    $expr = "icacls `"$finalPath`" /grant Everyone:F /T"
    Invoke-Expression $expr | Out-Null

    Write-Host " [SUCCESS] File ready at: $finalPath" -ForegroundColor Green
}

if ($Mode -eq "Receiver") {
    Show-Header
    Write-Host " [MODE: RECEIVER]" -ForegroundColor Yellow
    
    if (-not $RemoteHost -or -not $RemoteFile) { Write-Host " [!] Error: Missing RemoteHost or Filename." -ForegroundColor Red; return }

    Write-Host " Target: \\$RemoteHost\$RemoteShare\$RemoteFile" -ForegroundColor Gray
    
    # Credentials (Interactive request if running via Tool)
    # We assume the user has set the password or we prompt here if secure string isn't passed
    # For simplicity in RMM, we rely on the session prompts or passed args.
    
    try {
        $cred = Get-Credential "$RemoteHost\$RemoteUser"
    } catch {
        Write-Host " [!] Could not grab credentials. Aborting." -ForegroundColor Red
        return
    }

    Write-Host " Starting Background Job..." -ForegroundColor Cyan
    $jobName = "Transfer_$($RemoteFile.Substring(0, [math]::Min(10, $RemoteFile.Length)))"

    $job = Start-Job -Name $jobName -ScriptBlock {
        param($c, $rHost, $rShare, $fName)
        $dest = "$env:USERPROFILE\Downloads\"
        New-PSDrive -Name "Q" -PSProvider FileSystem -Root "\\$rHost\$rShare" -Credential $c -Persist | Out-Null
        $log = robocopy "Q:\" $dest $fName /Z /NP /R:5 /W:5
        Remove-PSDrive "Q"
        return $log
    } -ArgumentList $cred, $RemoteHost, $RemoteShare, $RemoteFile

    Write-Host " [SUCCESS] Job Started: $($job.Name)" -ForegroundColor Green
}

if ($Mode -eq "Status") {
    Show-Header
    $jobs = Get-Job | Where-Object { $_.Name -like "Transfer_*" }
    if ($jobs) {
        $jobs | Select-Object Id, Name, State, Location | Format-Table -AutoSize
        Write-Host " To view logs: Receive-Job -Name 'JobName' -Keep" -ForegroundColor Gray
    } else {
        Write-Host " No active transfer jobs." -ForegroundColor Yellow
    }
}