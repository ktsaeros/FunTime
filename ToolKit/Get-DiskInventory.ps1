<# .SYNOPSIS Smart Disk Inventory (Physical + WMI Fallback) #>
Write-Host "--- DISK INVENTORY ---" -ForegroundColor Cyan

# Try modern Storage module first (Server 2012+/Win10+)
if (Get-Command Get-PhysicalDisk -ErrorAction SilentlyContinue) {
    try {
        Get-PhysicalDisk | Select-Object FriendlyName, SerialNumber, BusType, MediaType, HealthStatus, Size, @{n='SizeGB';e={[math]::Round($_.Size/1GB,0)}} | Format-Table -AutoSize
        return # Exit if successful
    } catch {}
}

# Fallback to WMI (Legacy/Compatible)
Write-Warning "Modern storage cmdlets failed/missing. Using WMI fallback."
Get-CimInstance Win32_DiskDrive | Select-Object Index, Model, SerialNumber, InterfaceType, MediaType, Size, @{n='SizeGB';e={[math]::Round($_.Size/1GB,0)}} | Format-Table -AutoSize