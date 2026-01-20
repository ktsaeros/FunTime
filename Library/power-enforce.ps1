<#
.SYNOPSIS
    Enforces corporate power policies (v7 Final + Logging).
    
    LOGGING:
    - Writes activity to Console (Host) and C:\Aeros\PowerConfig_Log.txt
    
    POLICIES:
    - DESKTOP: High Perf, Always On, S0 Disabled, WOL Enabled.
    - LAPTOP:  
        - AC: Balanced, NEVER SLEEP (Lid Open or Closed).
        - DC: Balanced, Sleep 15m (Lid Open), Sleep Immediate (Lid Closed).
    - GLOBAL: Fast Startup Disabled.

.PARAMETER PowerButtonAction
    0=Do Nothing, 1=Sleep, 2=Hibernate, 3=Shutdown. Default: 1 (Sleep).
#>

[CmdletBinding()]
param(
    [switch]$ForceReboot,
    
    [ValidateSet(0,1,2,3)]
    [int]$PowerButtonAction = 1 
)

# --- 0. Setup Logging & Paths ---
$LogDir  = "C:\Aeros"
$LogFile = "$LogDir\PowerConfig_Log.txt"

if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

function Write-Log {
    param([string]$Message, [string]$Color = "White")
    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogLine   = "[$TimeStamp] $Message"
    
    # Write to Console (for RMM)
    Write-Host $Message -ForegroundColor $Color
    
    # Append to File
    Add-Content -Path $LogFile -Value $LogLine -Force
}

# --- 1. Admin Safety Check ---
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    Write-Error "Must run as Administrator."
    return
}

Write-Log "=== Starting Power Policy Enforcement (v7) ===" "Cyan"

# --- 2. Configuration Constants ---
$SUB_BUTTONS = '4f971e89-eebd-4455-a8de-9e59040e7347'
$PBUTTON     = '7648efa3-dd9c-4e3e-b566-50f929386280' # Power Button
$SBUTTON     = '96996bc0-ad50-47ec-923b-6f41874dd9eb' # Sleep Button
$LIDACTION   = '5ca83367-6e45-459f-a27b-476b1d01c936' # Lid Close
$ACTION_NONE = 0
$ACTION_SLEEP= 1

# --- 3. Helper Functions ---

function Get-MachineType {
    $chassis = Get-CimInstance -ClassName Win32_SystemEnclosure -ErrorAction SilentlyContinue
    $laptopTypes = @(8, 9, 10, 11, 12, 14, 18, 21, 30, 31, 32)
    
    # Robust Battery Check (Ignore UPS)
    $battery = Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue | 
               Where-Object { $_.Name -notmatch 'UPS|Uninterruptible' }

    # Robust Chassis Check
    $isLaptopChassis = $false
    if ($chassis -and $chassis.ChassisTypes) {
        $isLaptopChassis = ($chassis.ChassisTypes | Where-Object { $_ -in $laptopTypes })
    }

    if ($isLaptopChassis -or $battery) { return "Laptop" }
    return "Desktop"
}

function Disable-FastStartup {
    Write-Log "Configuring: Disabling 'Fast Startup' (HiberbootEnabled)..." "Gray"
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power"
    
    try {
        Set-ItemProperty -Path $regPath -Name "HiberbootEnabled" -Value 0 -Type DWord -ErrorAction Stop
    } catch {
        Write-Log "Error disabling Fast Startup: $_" "Red"
    }
}

function Set-ButtonBehavior {
    param($SchemeGuid, $IsLaptop, $BtnAction)
    
    Write-Log "Configuring: Buttons (Power=$BtnAction) and Lid Logic..." "Gray"

    # Physical Power Button & Sleep Button
    powercfg -setacvalueindex $SchemeGuid $SUB_BUTTONS $PBUTTON $BtnAction
    powercfg -setdcvalueindex $SchemeGuid $SUB_BUTTONS $PBUTTON $BtnAction
    powercfg -setacvalueindex $SchemeGuid $SUB_BUTTONS $SBUTTON $ACTION_SLEEP
    powercfg -setdcvalueindex $SchemeGuid $SUB_BUTTONS $SBUTTON $ACTION_SLEEP

    if ($IsLaptop) {
        # AC (Plugged In): Do Nothing (User Request: "AC/Sleep/Never")
        powercfg -setacvalueindex $SchemeGuid $SUB_BUTTONS $LIDACTION $ACTION_NONE
        
        # DC (Battery): Sleep (Safety)
        powercfg -setdcvalueindex $SchemeGuid $SUB_BUTTONS $LIDACTION $ACTION_SLEEP
    }
    
    powercfg -setactive $SchemeGuid
}

# --- 4. Profile: Desktop (Always On) ---
function Set-DesktopPolicy {
    Write-Log "--- Applying DESKTOP Policy ---" "Green"
    
    # High Perf
    $highPerf = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
    powercfg /s $highPerf
    if ($LASTEXITCODE -ne 0) { 
        powercfg /s 381b4222-f694-41f0-9685-ff5bb260df2e 
        $highPerf = "381b4222-f694-41f0-9685-ff5bb260df2e"
        Write-Log "Notice: High Performance plan missing, falling back to Balanced." "Yellow"
    }

    # Timeouts: Never Sleep/Hibernate
    powercfg /change monitor-timeout-ac 20
    powercfg /change disk-timeout-ac 0
    powercfg /change standby-timeout-ac 0
    powercfg /change hibernate-timeout-ac 0
    powercfg /h off 

    Set-ButtonBehavior -SchemeGuid $highPerf -IsLaptop $false -BtnAction $PowerButtonAction

    # Modern Standby (S0) Disable
    $regPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Power'
    $regName = 'PlatformAoAcOverride'
    $current = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).$regName
    
    if ($current -ne 0) {
        Write-Log "Action: Disabling Modern Standby (S0) via Registry. Previous Value: $current" "Yellow"
        New-ItemProperty -Path $regPath -Name $regName -PropertyType DWord -Value 0 -Force | Out-Null
        $script:RebootRequired = $true
    } else {
        Write-Log "Check: Modern Standby (S0) already disabled." "Gray"
    }

# --- Aggressive NIC Keep-Alive ---
    $nics = Get-NetAdapter -Physical
    foreach ($nic in $nics) {
        Write-Log "Configuring NIC: $($nic.Name)" "Gray"
        
        # 1. Enable WOL (Standard)
        Set-NetAdapterPowerManagement -Name $nic.Name -WakeOnMagicPacket Enabled -ErrorAction SilentlyContinue
        
        # 2. Force 'Do Not Sleep' -unchecks "Allow the computer to turn off this device to save power"
        try {
            Disable-NetAdapterPowerManagement -Name $nic.Name -ErrorAction Stop
            Write-Log "   -> Power Saving DISABLED (Always On)" "Cyan"
        }
        catch {
            Write-Log "   -> Failed to disable power saving: $_" "Red"
        }
    }
}

# --- 5. Profile: Laptop (Portable) ---
function Set-LaptopPolicy {
    Write-Log "--- Applying LAPTOP Policy ---" "Green"
    
    $balanced = "381b4222-f694-41f0-9685-ff5bb260df2e"
    powercfg /s $balanced
    
    # Restore Modern Standby (S0)
    $regPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Power'
    if (Get-ItemProperty -Path $regPath -Name 'PlatformAoAcOverride' -ErrorAction SilentlyContinue) {
        Write-Log "Action: Restoring Modern Standby (removing registry override)..." "Yellow"
        Remove-ItemProperty -Path $regPath -Name 'PlatformAoAcOverride' -Force
        $script:RebootRequired = $true
    }


    
    # Timeouts
    # AC: Monitor 20m, Sleep NEVER (0) -- User Request
    powercfg /change monitor-timeout-ac 20
    powercfg /change standby-timeout-ac 0
    powercfg /change hibernate-timeout-ac 0
    
    # DC: Monitor 10m, Sleep 15m
    powercfg /change monitor-timeout-dc 10
    powercfg /change standby-timeout-dc 15
    powercfg /change hibernate-timeout-dc 60
    powercfg /h on 

    Set-ButtonBehavior -SchemeGuid $balanced -IsLaptop $true -BtnAction $PowerButtonAction
}

# --- 6. Execution ---
$Type = Get-MachineType
Write-Log "Detected Chassis: $Type" "Green"
$script:RebootRequired = $false

Disable-FastStartup

if ($Type -eq "Laptop") { 
    Set-LaptopPolicy 
} else { 
    Set-DesktopPolicy 
}

# Final Report
if ($script:RebootRequired) {
    Write-Log "WARNING: Registry changes made (S0/Modern Standby). A REBOOT IS REQUIRED." "Red"
    if ($ForceReboot) { Restart-Computer -Force -TimeOut 10 }
} else {
    Write-Log "SUCCESS: Power policy applied. No reboot required." "Green"
}
