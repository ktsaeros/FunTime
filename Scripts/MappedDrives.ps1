# Get-MappedDrivesForAllUsers.ps1
# Run as Administrator on the local machine

Function Get-MappedDrivesForAllUsers {
    # Grab all loaded user hives (skip default/system)
    $sids = Get-ChildItem -Path Registry::HKEY_USERS |
        Where-Object { $_.Name -match '^S-1-5-21-' }

    foreach ($sidKey in $sids) {
        $sid = $sidKey.PSChildName
        try {
            # Translate SID to domain\username
            $ntAccount = (New-Object System.Security.Principal.SecurityIdentifier($sid))
                          .Translate([System.Security.Principal.NTAccount]).Value
        } catch {
            $ntAccount = $sid  # fallback if translation fails
        }

        # Path to that user's mapped drives in the registry
        $networkKeyPath = "Registry::HKEY_USERS\$sid\Network"
        if (Test-Path $networkKeyPath) {
            $drives = Get-ChildItem -Path $networkKeyPath
            foreach ($drv in $drives) {
                $props = Get-ItemProperty -Path $drv.PSPath
                [PSCustomObject]@{
                    User        = $ntAccount
                    DriveLetter = $drv.PSChildName
                    RemotePath  = $props.RemotePath
                    # You can also inspect other props like ProviderName, UserName, etc.
                }
            }
        }
    }
}

# Run it and output as a table
Get-MappedDrivesForAllUsers | 
    Sort-Object User, DriveLetter |
    Format-Table -AutoSize