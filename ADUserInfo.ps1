Function Get-ADUserInfo {
    param (
        [string]$domain
    )

    $users = Get-ADUser -Filter * -Property SamAccountName, DisplayName, LastLogonDate, LockedOut, PasswordExpired | Select-Object SamAccountName, DisplayName, LastLogonDate, LockedOut, PasswordExpired

    Write-Host "`nUser Information from Active Directory Domain: $domain"
    $users | ForEach-Object {
        $lockedStatus = if ($_.LockedOut) { "Yes" } else { "No" }
        $passwordStatus = if ($_.PasswordExpired) { "Expired" } else { "Valid" }
        Write-Host "-----------------------------------------"
        Write-Host "Username: $($_.SamAccountName)"
        Write-Host "Display Name: $($_.DisplayName)"
        Write-Host "Last Logon Date: $($_.LastLogonDate)"
        Write-Host "Locked Out: $lockedStatus"
        Write-Host "Password Status: $passwordStatus"
    }
}

Function Show-Menu {
    Param (
        [String]$MenuName
    )

    $MenuOptions = @(
        @{Option = '1'; Description = 'Get AD User Information'; Command = {
            $domain = Read-Host "Enter the Active Directory domain"
            Get-ADUserInfo -domain $domain
        }},
        @{Option = '2'; Description = 'Exit'; Command = { return }}
    )

    Write-Host "`n$MenuName"
    $MenuOptions | ForEach-Object { Write-Host "$($_.Option). $($_.Description)" }

    $selection = Read-Host "Choose an option"
    $selectedOption = $MenuOptions | Where-Object { $_.Option -eq $selection }

    if ($selectedOption) {
        & $selectedOption.Command
        if ($selection -ne '2') {
            Show-Menu -MenuName $MenuName
        }
    } else {
        Write-Host "Invalid selection, please try again." -ForegroundColor Red
        Show-Menu -MenuName $MenuName
    }
}

# Start the interactive menu
Show-Menu -MenuName "AD User Information Menu"
