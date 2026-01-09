<#
.SYNOPSIS
    Aeros Workgroup Transfer Helper (Toolbox Edition v2.1)
    Silent execution engine. Logic driven by AerosMaster parameters.
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
    [string]$RemoteUser = "transfer",
    [string]$RemotePass
)

# Fix Output Encoding
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

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

    # Ensure Dest Exists
    if (-not (Test-Path $DestPath)) {
        New-Item -Path $DestPath -ItemType Directory -Force | Out-Null
    }

    # Move File
    $fileName = Split-Path $SourcePath -Leaf
    $finalPath = Join-Path $DestPath $fileName
    
    Write-Host " Moving: $fileName" -ForegroundColor Gray
    Move-Item -Path $SourcePath -Destination $DestPath -Force

    # Fix Permissions
    Write-Host " Fixing Permissions..." -ForegroundColor Gray
    $expr = "icacls `"$finalPath`" /grant Everyone:F /T"
    Invoke-Expression $expr | Out-Null

    Write-Host " [SUCCESS] File ready at: $finalPath" -ForegroundColor Green
}

if ($Mode -eq "Receiver") {
    Show-Header
    Write-Host " [MODE: RECEIVER]" -ForegroundColor Yellow
    
    if (-not $RemoteHost -or -not $RemoteFile) { Write-Host " [!] Error: Missing RemoteHost or Filename." -ForegroundColor Red; return }

    try {
        if ($RemotePass) {
            $secPass = ConvertTo-SecureString $RemotePass -AsPlainText -Force
            $cred = New-Object System.Management.Automation.PSCredential ("$RemoteHost\$RemoteUser", $secPass)
        } else {
            $cred = Get-Credential "$RemoteHost\$RemoteUser"
        }
    } catch {
        Write-Host " [!] Credential Error: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    Write-Host " Starting Background Job for: $RemoteFile" -ForegroundColor Cyan
    $jobName = "Transfer_$($RemoteFile.Substring(0, [math]::Min(10, $RemoteFile.Length)))"

    $job = Start-Job -Name $jobName -ScriptBlock {
        param($c, $rHost, $rShare, $fName)
        $dest = "$env:USERPROFILE\Downloads\"
        
        # Robust Drive Mapping
        if (Test-Path "Q:") { Remove-PSDrive "Q" -Force -ErrorAction SilentlyContinue }
        
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