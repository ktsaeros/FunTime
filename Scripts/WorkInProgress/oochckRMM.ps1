# --- Office Lifecycle Check for RMM ---
# Detects installed Office (Click-to-Run) and flags if unsupported / past EOS.

function Get-OfficeSkuClassification {
    param([Parameter(Mandatory)][string[]]$Ids)
    $matched = foreach ($id in $Ids) {
        $family = $null; $year = $null; $license = $null
        if ($id -match '^(O365|Microsoft365|O365ProPlusRetail|O365BusinessRetail)') {
            $family='M365'; $license='Subscription'
        }
        elseif ($id -match '2024.*Retail|2024.*Volume|LTSC2024') {
            $family='Office2024'; $year='2024'; $license='Perpetual'
        }
        elseif ($id -match '2021.*Retail|2021.*Volume|LTSC2021') {
            $family='Office2021'; $year='2021'; $license='Perpetual'
        }
        elseif ($id -match '2019.*Retail|2019.*Volume') {
            $family='Office2019'; $year='2019'; $license='Perpetual'
        }
        elseif ($id -match '(^|,|\s)(ProPlusRetail|ProfessionalRetail|StandardRetail|HomeBusinessRetail|HomeStudentRetail)(\s|,|$)') {
            $family='Office2016'; $year='2016'; $license='Perpetual'
        }
        [pscustomobject]@{ ProductReleaseId=$id; Family=$family; Year=$year; License=$license }
    }

    # Force arrays so indexing like [-1] never hits a string
    $families = @($matched | Where-Object Family | Select-Object -ExpandProperty Family -Unique)
    $years    = @($matched | Where-Object Year   | Select-Object -ExpandProperty Year   -Unique)

    [pscustomobject]@{ Families=$families; Years=$years }
}

# --- Lifecycle Metadata ---
$LifecycleMap = @{
    'M365'       = [pscustomobject]@{ Name='Microsoft 365 Apps'; Policy='Modern Lifecycle (continuous)'; EOS=$null;              Notes='Subscription; serviced while in support.' }
    'Office2024' = [pscustomobject]@{ Name='Office 2024';       Policy='Modern Lifecycle (5 years, no extended)'; EOS=[datetime]'2029-10-09'; Notes='Home & Business/Home editions' }
    'Office2021' = [pscustomobject]@{ Name='Office 2021';       Policy='Modern Lifecycle (5 years, no extended)'; EOS=[datetime]'2026-10-13'; Notes='Home & Business/Home/Professional' }
    'Office2019' = [pscustomobject]@{ Name='Office 2019';       Policy='Fixed (5 + 2)';                         EOS=[datetime]'2025-10-14'; Notes='Support ended Oct 14, 2025' }
    'Office2016' = [pscustomobject]@{ Name='Office 2016';       Policy='Fixed (5 + 5)';                         EOS=[datetime]'2025-10-14'; Notes='Support ended Oct 14, 2025' }
    'Office2013' = [pscustomobject]@{ Name='Office 2013';       Policy='Fixed (5 + 5)';                         EOS=[datetime]'2023-04-11'; Notes='Unsupported' }
    'Office2010' = [pscustomobject]@{ Name='Office 2010';       Policy='Fixed (5 + 5)';                         EOS=[datetime]'2020-10-13'; Notes='Unsupported' }
}

# --- Detect Office (Click-to-Run) ---
$regPath = 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration'
$c2r = Get-ItemProperty -LiteralPath $regPath -ErrorAction SilentlyContinue
if (-not $c2r) {
    # No C2R – look for MSI Office (2016/2013/2010) so we can describe it better
    $msiVersions = @()

    foreach ($ver in @('16.0','15.0','14.0')) {
        $path1 = "HKLM:\SOFTWARE\Microsoft\Office\$ver\Outlook"
        $path2 = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\$ver\Outlook"

        if ( (Test-Path -LiteralPath $path1 -ErrorAction SilentlyContinue) -or
             (Test-Path -LiteralPath $path2 -ErrorAction SilentlyContinue) ) {
            $msiVersions += $ver
        }
    }

    if ($msiVersions.Count -gt 0) {
        $latest = ($msiVersions | Sort-Object)[-1]
        switch ($latest) {
            '16.0' { $msiFamily = 'Office2016' }
            '15.0' { $msiFamily = 'Office2013' }
            '14.0' { $msiFamily = 'Office2010' }
            default { $msiFamily = $null }
        }

        $lifecycle = $null
        if ($msiFamily -and $LifecycleMap.ContainsKey($msiFamily)) {
            $lifecycle = $LifecycleMap[$msiFamily]
        }

        if ($lifecycle) {
            Write-Output "No Click-to-Run Office detected."
            Write-Output ("MSI-based {0} appears to be installed (Office build {1})." -f $lifecycle.Name, $latest)
            if ($lifecycle.EOS) {
                Write-Output ("End of Support: {0:yyyy-MM-dd}" -f $lifecycle.EOS)
                Write-Output ("Notes: {0}" -f $lifecycle.Notes)
            }
            else {
                Write-Output "End of Support: (ongoing)"
                Write-Output ("Notes: {0}" -f $lifecycle.Notes)
            }
            Write-Output ""
            Write-Output ("FAIL: {0} (MSI) is not an approved Office build on this workstation." -f $lifecycle.Name)
        }
        else {
            Write-Output "No Click-to-Run Office detected. MSI Office footprints found, but version could not be classified."
            Write-Output "FAIL: Unclassified MSI Office installation."
        }
    }
    else {
        Write-Output "No Microsoft Office Click-to-Run or MSI 2010/2013/2016 footprint detected."
        Write-Output "FAIL: Office not detected or not a supported SKU."
    }

    exit 1
}

# --- Detect platform (x86/x64) ---
$officePlatformRaw = $c2r.Platform
switch ($officePlatformRaw) {
    'x64' { $officePlatform = '64-bit' }
    'x86' { $officePlatform = '32-bit' }
    default { $officePlatform = 'Unknown' }
}

$skuIds = $c2r.ProductReleaseIds -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
$skuInfo = Get-OfficeSkuClassification -Ids $skuIds

# Always pick the last family safely, even if there's only one
$family = if ($skuInfo.Families.Count -gt 0) { ($skuInfo.Families | Select-Object -Last 1) } else { 'Unknown' }
$lifecycle = $LifecycleMap[$family]

# Output
Write-Output "Detected SKUs: $($skuIds -join ', ')"
Write-Output ("Detected Family: {0}" -f ($(if ($lifecycle) { $lifecycle.Name } else { $family })))
Write-Output ("Platform: {0}" -f $officePlatform)
Write-Output "VersionToReport: $($c2r.VersionToReport)"
if ($lifecycle -and $lifecycle.EOS) {
    Write-Output ("End of Support: {0:yyyy-MM-dd}" -f $lifecycle.EOS)
} else {
    Write-Output "End of Support: (ongoing)"
}
Write-Output ("Notes: {0}" -f ($(if ($lifecycle) { $lifecycle.Notes } else { 'No lifecycle mapping for detected family.' })))
Write-Output ""

# --- Evaluate Support Status ---
$today = Get-Date
$supportedFamilies = @('M365','Office2024')

# Fail if Office is 64-bit
if ($officePlatform -eq '64-bit') {
    Write-Output "FAIL: Microsoft Office 64-bit installation detected. Use 32-bit Office for compatibility."
    exit 1
}

if ($supportedFamilies -contains $family) {
    Write-Output "PASS: Supported Office build detected ($($(if ($lifecycle){$lifecycle.Name}else{$family})))."
    exit 0
}
elseif ($lifecycle -and $lifecycle.EOS -and $today -gt $lifecycle.EOS) {
    Write-Output "FAIL: $($lifecycle.Name) is past end of support ($($lifecycle.EOS.ToString('yyyy-MM-dd')))."
    exit 1
}
else {
    Write-Output "FAIL: Unsupported or unknown Office version ($family)."
    exit 1
}