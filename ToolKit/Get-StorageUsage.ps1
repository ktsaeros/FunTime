<#
.SYNOPSIS
    Storage Analysis Tools
#>

Write-Host "1. Scan Subfolder Sizes (Get-FolderSize)"
Write-Host "2. Find Largest Files (Get-FileSizes)"
$sel = Read-Host "Select Option"

$path = Read-Host "Enter Path (e.g. C:\Users)"
if (-not (Test-Path $path)) { Write-Error "Path not found"; return }

if ($sel -eq '1') {
    Write-Host "Scanning..." -ForegroundColor Cyan
    Get-ChildItem -Path $path -Directory | ForEach-Object {
        $size = (Get-ChildItem -Path $_.FullName -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1MB
        [PSCustomObject]@{ Name = $_.Name; "Size(MB)" = [math]::Round($size, 2) }
    } | Sort-Object "Size(MB)" -Descending | Format-Table -AutoSize
}
elseif ($sel -eq '2') {
    Write-Host "Scanning..." -ForegroundColor Cyan
    Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue | 
        Sort-Object Length -Descending | 
        Select-Object -First 20 Name, @{N='Size(MB)';E={[math]::Round($_.Length / 1MB, 2)}}, Directory |
        Format-Table -AutoSize
}