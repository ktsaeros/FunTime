<#
.SYNOPSIS
    AEROS MASTER TOOLKIT (Hybrid Launcher v1.0)
    Acts as a central menu that fetches and runs individual tools from GitHub.
#>

# ==============================================================================
#  CORE LAUNCHER ENGINE
# ==============================================================================

function Invoke-AerosScript {
    <# 
    .SYNOPSIS
        Downloads a script from your GitHub Repo and runs it in an isolated scope.
        This prevents variables from the script clashing with the menu.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$ScriptName
    )

    $BaseUrl = "https://raw.githubusercontent.com/ktsaeros/FunTime/main/ToolKit"
    $TargetUrl = "$BaseUrl/$ScriptName"

    Write-Host "   [Launcher] Fetching $ScriptName..." -ForegroundColor Cyan

    try {
        # 1. Force TLS 1.2 (Crucial for GitHub)
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        
        # 2. Download the code
        $WebClient = New-Object System.Net.WebClient
        $Code = $WebClient.DownloadString($TargetUrl)

        # 3. Execute in a CHILD SCOPE using & { ... }
        #    This is the magic sauce. Variables defined inside $ScriptName 
        #    will die when the script finishes, keeping your RAM clean.
        & {
            Invoke-Expression $Code
        }
    }
    catch {
        Write-Error "Failed to launch $ScriptName."
        Write-Error "Error: $($_.Exception.Message)"
        Write-Warning "Check your internet connection or if the file exists on GitHub."
    }
}

# ==============================================================================
#  TOOL WRAPPERS
# ==============================================================================

function Get-OfficeAudit {
    # Calls the standalone complex script
    Invoke-AerosScript -ScriptName "oochk.ps1"
}

# ==============================================================================
#  MAIN MENU
# ==============================================================================

function Start-Aeros {
    while ($true) {
        Clear-Host
        Write-Host "╔═══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
        Write-Host "║           AEROS MASTER TOOLKIT (Hybrid)               ║" -ForegroundColor Cyan
        Write-Host "╚═══════════════════════════════════════════════════════╝" -ForegroundColor Cyan
        
        Write-Host " [DIAGNOSTICS]" -ForegroundColor Yellow
        Write-Host "  4.  Outlook/Office Audit (Launches oochk.ps1)" -ForegroundColor White
        
        Write-Host "`n [DEPLOYMENT]" -ForegroundColor Yellow
        Write-Host "  (More tools coming soon...)" -ForegroundColor DarkGray
        
        Write-Host "`n Q. Quit" -ForegroundColor DarkCyan
        
        $sel = Read-Host "`n Command"
        
        switch ($sel) {
            '4'  { Get-OfficeAudit; pause }
            
            'Q'  { return }
            'q'  { return }
        }
    }
}

# Auto-start menu if run interactively
if ($Host.Name -notmatch "ISE|Visual Studio Code") {
    Start-Aeros
}