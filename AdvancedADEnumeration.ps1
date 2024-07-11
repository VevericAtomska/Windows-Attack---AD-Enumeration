Function Get-ADInformation {
    param (
        [string]$domain
    )

    # Get Domain Controllers
    $domainControllers = Get-ADDomainController -Filter * | Select-Object Hostname, Site, IPv4Address
    Write-Host "`nDomain Controllers:"
    $domainControllers | Format-Table -AutoSize

    # Get Users
    $users = Get-ADUser -Filter * -Property SamAccountName, DisplayName, LastLogonDate, LockedOut, PasswordExpired | 
             Select-Object SamAccountName, DisplayName, LastLogonDate, LockedOut, PasswordExpired
    Write-Host "`nUsers:"
    $users | Format-Table -AutoSize

    # Get Privileged Users
    $privUsers = Get-ADUser -Filter {AdminCount -eq 1} -Property SamAccountName, DisplayName, LastLogonDate, LockedOut, PasswordExpired |
                 Select-Object SamAccountName, DisplayName, LastLogonDate, LockedOut, PasswordExpired
    Write-Host "`nPrivileged Users:"
    $privUsers | Format-Table -AutoSize

    # Get Groups
    $groups = Get-ADGroup -Filter * -Property SamAccountName, GroupCategory, GroupScope, Members |
              Select-Object SamAccountName, GroupCategory, GroupScope, Members
    Write-Host "`nGroups:"
    $groups | Format-Table -AutoSize

    # Get Computers
    $computers = Get-ADComputer -Filter * -Property Name, OperatingSystem, LastLogonDate |
                 Select-Object Name, OperatingSystem, LastLogonDate
    Write-Host "`nComputers:"
    $computers | Format-Table -AutoSize

    # Get Organizational Units
    $ous = Get-ADOrganizationalUnit -Filter * -Property DistinguishedName, Name |
           Select-Object DistinguishedName, Name
    Write-Host "`nOrganizational Units:"
    $ous | Format-Table -AutoSize

    # Get DNS Zones
    $dnsZones = Get-DnsServerZone -ComputerName $domain
    Write-Host "`nDNS Zones:"
    $dnsZones | Format-Table -AutoSize

    # Get Service Principal Names
    $spns = Get-ADObject -Filter { ServicePrincipalName -like "*" } -Property ServicePrincipalName |
            Select-Object Name, ServicePrincipalName
    Write-Host "`nService Principal Names:"
    $spns | Format-Table -AutoSize

    # Get GPOs
    $gpos = Get-GPO -All | Select-Object DisplayName, GpoStatus, Owner, CreationTime, ModificationTime
    Write-Host "`nGroup Policy Objects:"
    $gpos | Format-Table -AutoSize

    # Get Trust Relationships
    $trusts = Get-ADTrust -Filter * | Select-Object Name, Source, Target, TrustType, TrustDirection, IsTransitive
    Write-Host "`nTrust Relationships:"
    $trusts | Format-Table -AutoSize

    # Check for Weak Passwords
    Write-Host "`nChecking for Weak Passwords (e.g., password=password)"
    $weakPasswords = @("password", "123456", "welcome", "password1", "12345", "123456789")
    foreach ($weakPassword in $weakPasswords) {
        $usersWithWeakPasswords = Get-ADUser -Filter * -Property SamAccountName | Where-Object { 
            (Get-ADUser $_.SamAccountName -Properties * | Select-Object -ExpandProperty PasswordLastSet) -eq $null -and
            (ConvertTo-SecureString -String $weakPassword -AsPlainText -Force | Get-ADUser -Filter {UserPassword -eq $_}).SamAccountName
        }
        if ($usersWithWeakPasswords) {
            Write-Host "`nUsers with password '$weakPassword':"
            $usersWithWeakPasswords | Format-Table -AutoSize
        }
    }

    # Identify Users with Never Expiring Passwords
    $neverExpiringPasswords = Get-ADUser -Filter {PasswordNeverExpires -eq $true} -Property SamAccountName, DisplayName, PasswordNeverExpires |
                              Select-Object SamAccountName, DisplayName, PasswordNeverExpires
    Write-Host "`nUsers with Never Expiring Passwords:"
    $neverExpiringPasswords | Format-Table -AutoSize
}

Function Show-Menu {
    Param (
        [String]$MenuName
    )

    $MenuOptions = @(
        @{Option = '1'; Description = 'Enumerate AD Information'; Command = {
            $domain = Read-Host "Enter the Active Directory domain"
            Get-ADInformation -domain $domain
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
Show-Menu -MenuName "Advanced AD Enumeration Menu"
