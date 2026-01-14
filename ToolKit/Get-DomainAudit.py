function Get-DomainAudit {
    $ScriptName = "Get-DomainAudit.py"
    $RepoRoot   = "https://raw.githubusercontent.com/ktsaeros/FunTime/main/ToolKit"
    $TargetUrl  = "$RepoRoot/$ScriptName"
    $TempPath   = "$env:TEMP\$ScriptName"
    
    # 1. Check Python
    if (Get-Command "python3" -ErrorAction SilentlyContinue) { $PyCmd = "python3" }
    elseif (Get-Command "python" -ErrorAction SilentlyContinue) { $PyCmd = "python" }
    else { Write-Error "Python is not installed or not in your PATH."; return }

    # 2. Debug Output
    Write-Host "   [Debug] Target URL: $TargetUrl" -ForegroundColor DarkGray
    
    try {
        Write-Host "   [Tool] Downloading: $ScriptName..." -ForegroundColor Cyan
        
        # Verbose error handling for download
        try {
            Invoke-WebRequest -Uri $TargetUrl -OutFile $TempPath -UseBasicParsing -Headers @{ "Cache-Control" = "no-cache" } -ErrorAction Stop
        } catch {
            throw "Download Failed. HTTP Status: $($_.Exception.Response.StatusCode.value__) ($($_.Exception.Message))"
        }

        # 3. Check if file is empty (common GitHub error)
        if ((Get-Item $TempPath).Length -lt 100) {
            $Content = Get-Content $TempPath -Raw
            if ($Content -match "404: Not Found") { throw "File downloaded but contains GitHub 404 error." }
        }

        # 4. Execute
        Write-Host "   [Exec] Launching Python..." -ForegroundColor Green
        & $PyCmd $TempPath
        
        # Cleanup
        Remove-Item $TempPath -ErrorAction SilentlyContinue
    }
    catch {
        Write-Error "ERROR: $_"
    }
}