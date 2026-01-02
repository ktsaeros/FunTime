<#
.SYNOPSIS
    Generates 10 "Database Safe" passphrases using your custom dictionary.
    Format: Word(4-6) + 2DigitNum(NonSeq) + Symbol + Word(4-6)
    Example: Blue42#Tank
#>

Function Get-AerosWord {
    # UPDATED: Points to YOUR repo now
    $url = 'https://raw.githubusercontent.com/ktsaeros/FunTime/main/Dictionaries/words.txt'
    
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        # Download and cache the list for speed
        if (-not $global:AerosWordList) {
            $global:AerosWordList = (Invoke-RestMethod -Uri $url -ErrorAction Stop) -split "`n" | ForEach-Object { $_.Trim() }
        }
        
        # Filter: Safety check for length (4-6 chars)
        $valid = $global:AerosWordList | Where-Object { $_.Length -ge 4 -and $_.Length -le 6 }
        return ($valid | Get-Random)
    } catch {
        # Offline Fallback (Just in case GitHub is down)
        return (Get-Random -InputObject @("Blue","Fast","Safe","Hard","Cool","Wise","Main","Core","Data","Byte","Code","Node","File","View","Zoom","Task"))
    }
}

Function New-Passphrase {
    $w1 = Get-AerosWord
    $w2 = Get-AerosWord
    
    # 1. Title Case (First letter cap, rest lower)
    $w1 = $w1.Substring(0,1).ToUpper() + $w1.Substring(1).ToLower()
    $w2 = $w2.Substring(0,1).ToUpper() + $w2.Substring(1).ToLower()
    
    # 2. Non-Sequential Number (Avoids 12, 11, 89)
    do {
        $num = Get-Random -Min 10 -Max 99
        $s = [string]$num
        # Logic: Digits shouldn't match, and shouldn't be +1 or -1 of each other
        $isBad = ($s[0].ToInt32($null) + 1 -eq $s[1].ToInt32($null)) -or 
                 ($s[0].ToInt32($null) - 1 -eq $s[1].ToInt32($null)) -or
                 ($s[0] -eq $s[1])
    } while ($isBad)
    
    # 3. Database Safe Symbols (No ' " ; \ / `)
    $sym = (Get-Random -InputObject @('!','@','#','$','%','*','+','=','_','?'))
    
    # 4. Assemble: Word + Num + Sym + Word
    return "$w1$num$sym$w2"
}

Write-Host "--- PASSWORD GENERATOR (10 Options) ---" -ForegroundColor Cyan
Write-Host "Fetching dictionary..." -ForegroundColor Gray

# Clear cache on fresh run to ensure we get new words if updated
$global:AerosWordList = $null

1..10 | ForEach-Object {
    $pw = New-Passphrase
    Write-Host "Option $_`:  " -NoNewline -ForegroundColor DarkGray
    Write-Host "$pw" -ForegroundColor Yellow
}
Write-Host "`nDone." -ForegroundColor Green