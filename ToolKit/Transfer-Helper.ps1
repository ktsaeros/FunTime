<#
.SYNOPSIS
    Aeros Transfer Wizard v4.1 (Zip-and-Ship + Auto-Extract)
    - SENDER: Zips Source -> C:\Aeros\Transfer\Transfer.zip
    - RECEIVER: Pulls Zip -> C:\Aeros\Transfer -> Unzips -> Deletes Zip
    - CLEANUP: Nukes temp assets.
#>

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("Sender","Receiver","Status","Cleanup")]
    [string]$Mode,

    # Sender Params
    [string]$SourcePath,
    
    # Receiver Params
    [string]$RemoteHost,
    [string]$RemotePass
)

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# --- CONSTANTS ---
$BaseDir   = "C:\Aeros\Transfer"
$ZipFile   = "$BaseDir\Transfer.zip"
$ShareName = "Transfer"
$TransUser = "transfer"

function Show-Header {
    Write-Host "+-------------------------------------------------------+" -ForegroundColor Cyan
    Write-Host "|         AEROS ZIP-AND-SHIP WIZARD (v4.1)              |" -ForegroundColor Cyan
    Write-Host "+-------------------------------------------------------+" -ForegroundColor Cyan
}

# --- SENDER MODE ---
if ($Mode -eq "Sender") {
    Show-Header
    Write-Host " [MODE: SENDER]" -ForegroundColor Yellow

    if (-not (Test-Path $SourcePath)) { Write-Host " [!] Source not found." -ForegroundColor Red; return }

    # 1. Prepare Staging Area
    if (Test-Path $BaseDir) { Remove-Item $BaseDir -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -Path $BaseDir -ItemType Directory -Force | Out-Null

    # 2. Compress Data
    Write-Host " Compressing source to Transfer.zip..." -ForegroundColor Cyan
    try {
        Compress-Archive -Path $SourcePath -DestinationPath $ZipFile -Force -ErrorAction Stop
    } catch {
        Write-Host " [!] Zipping Failed: $($_.Exception.Message)" -ForegroundColor Red; return
    }

    # 3. Create/Reset User
    $genPass = "Aeros" + (Get-Random -Minimum 1000 -Maximum 9999) + "!"
    $securePass = ConvertTo-SecureString $genPass -AsPlainText -Force
    
    $u = Get-LocalUser -Name $TransUser -ErrorAction SilentlyContinue
    if ($u) { 
        Set-LocalUser -Name $TransUser -Password $securePass 
        Write-Host " [=] Updated password for existing user '$TransUser'" -ForegroundColor Gray
    } else {
        New-LocalUser -Name $TransUser -Password $securePass -Description "Aeros Transfer Temp" | Out-Null
        Add-LocalGroupMember -Group "Users" -Member $TransUser
        Write-Host " [+] Created User '$TransUser'" -ForegroundColor Green
    }
    
    Write-Host "     PASSWORD: $genPass" -ForegroundColor Yellow

    # 4. Create Share
    $s = Get-SmbShare -Name $ShareName -ErrorAction SilentlyContinue
    if (-not $s) {
        New-SmbShare -Name $ShareName -Path $BaseDir -FullAccess "Everyone" | Out-Null
        Write-Host " [+] Created Share '$ShareName'" -ForegroundColor Green
    }

    # 5. Perms
    $expr = "icacls `"$BaseDir`" /grant Everyone:F /T"
    Invoke-Expression $expr | Out-Null

    Write-Host "`n [SUCCESS] READY TO SHIP" -ForegroundColor Green
    Write-Host " Source: \\$env:COMPUTERNAME\$ShareName\Transfer.zip"
}

# --- RECEIVER MODE ---
if ($Mode -eq "Receiver") {
    Show-Header
    Write-Host " [MODE: RECEIVER]" -ForegroundColor Yellow
    
    if (-not $RemoteHost -or -not $RemotePass) { Write-Host " [!] Missing Info." -ForegroundColor Red; return }

    # Hardcoded Defaults
    $RemoteShare = "Transfer"
    $RemoteFile  = "Transfer.zip"
    $RemoteUser  = "transfer"
    
    # NEW: Updated Destination
    $LocalDest   = "C:\Aeros\Transfer" 

    # Creds
    $secPass = ConvertTo-SecureString $RemotePass -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential ("$RemoteHost\$RemoteUser", $secPass)

    Write-Host " Pulling content from \\$RemoteHost..." -ForegroundColor Cyan
    Write-Host " Final Destination: $LocalDest" -ForegroundColor Gray

    $jobName = "Pull_Zip_$(Get-Random)"
    
    # Start the "Robocopy + Unzip + Cleanup" Pipeline
    $job = Start-Job -Name $jobName -ScriptBlock {
        param($c, $rHost, $rShare, $fName, $lDest)
        
        # 1. Ensure Local Dest Exists
        if (-not (Test-Path $lDest)) { New-Item -Path $lDest -ItemType Directory -Force | Out-Null }

        # 2. Map Drive
        if (Test-Path "Q:") { Remove-PSDrive "Q" -Force -ErrorAction SilentlyContinue }
        try {
            New-PSDrive -Name "Q" -PSProvider FileSystem -Root "\\$rHost\$rShare" -Credential $c -Persist -ErrorAction Stop | Out-Null
        } catch { return "ERROR: Map Failed. Check Password." }
        
        # 3. Transfer Zip
        $log = robocopy "Q:\" $lDest $fName /Z /NP /R:5 /W:5
        Remove-PSDrive "Q"
        
        # 4. Unzip & Cleanup
        $zipPath = Join-Path $lDest $fName
        if (Test-Path $zipPath) {
            $log += "`r`n`r`n [POST-PROCESS] Unzipping to $lDest..."
            try {
                Expand-Archive -Path $zipPath -DestinationPath $lDest -Force -ErrorAction Stop
                $log += " Done."
                
                Remove-Item $zipPath -Force
                $log += "`r`n [POST-PROCESS] Deleted $fName (Cleanup)."
            } catch {
                $log += "`r`n [!] Unzip Failed: $($_.Exception.Message)"
            }
        } else {
            $log += "`r`n [!] Error: Zip file not found after transfer."
        }
        
        return $log
    } -ArgumentList $cred, $RemoteHost, $RemoteShare, $RemoteFile, $LocalDest

    Write-Host " [SUCCESS] Job Started: $($job.Name)" -ForegroundColor Green
    Write-Host " (Go to Main Menu -> Option 3 to check progress)" -ForegroundColor Gray
}

# --- CLEANUP MODE ---
if ($Mode -eq "Cleanup") {
    Show-Header
    Write-Host " [MODE: CLEANUP]" -ForegroundColor Red
    
    # 1. Remove Share
    if (Get-SmbShare -Name $ShareName -ErrorAction SilentlyContinue) {
        Remove-SmbShare -Name $ShareName -Force -ErrorAction SilentlyContinue
        Write-Host " [-] Removed Share '$ShareName'" -ForegroundColor Yellow
    }

    # 2. Remove User
    if (Get-LocalUser -Name $TransUser -ErrorAction SilentlyContinue) {
        Remove-LocalUser -Name $TransUser -ErrorAction SilentlyContinue
        Write-Host " [-] Removed User '$TransUser'" -ForegroundColor Yellow
    }

    # 3. Remove Files
    if (Test-Path $BaseDir) {
        Remove-Item $BaseDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host " [-] Removed Folder '$BaseDir'" -ForegroundColor Yellow
    }
    
    Write-Host "`n [CLEAN] System restored to normal." -ForegroundColor Green
}

# --- STATUS MODE ---
if ($Mode -eq "Status") {
    Show-Header
    $jobs = Get-Job | Where-Object { $_.Name -like "Pull_Zip_*" }
    
    if ($jobs) {
        $jobs | Select-Object Id, Name, State, Location | Format-Table -AutoSize
        Write-Host " Enter Job ID to view logs (or Press Enter to exit):" -NoNewline
        $id = Read-Host
        if ($id) {
            $j = Get-Job -Id $id -ErrorAction SilentlyContinue
            if ($j) {
                Write-Host "`n --- LOG OUTPUT ---" -ForegroundColor Yellow
                Receive-Job -Id $j.Id -Keep
                Write-Host " --- END LOG --- `n" -ForegroundColor Yellow
            }
        }
    } else {
        Write-Host " No active Zip transfers." -ForegroundColor Yellow
    }
}