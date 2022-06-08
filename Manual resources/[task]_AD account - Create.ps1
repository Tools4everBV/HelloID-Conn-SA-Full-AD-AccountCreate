$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# variables configured in form
$blnexpdate = $form.blnexpdate
$defaultGroups = $form.ou.groups
$department = $form.department
$displayName = $form.naming.displayname
$employeeType = $form.ou.type
$expiredate = $form.expiredate
$firstname = $form.givenname
$lastname = $form.lastname
$middlename = $form.middlename
$ou = $form.ou.Path
$password = $form.password
$sAMAccountName = $form.naming.samaccountname
$userPrincipalName = $form.naming.UserPrincipalName

try {
    #check existing AD user
    $adUser = Get-ADuser -Filter { UserPrincipalName -eq $userPrincipalName } | Select-Object SID
    if ([string]::IsNullOrEmpty($adUser)) {
        if ($blnexpdate -ne 'true') {
            $expDate = $null
        }
        else {
            $expDate = [datetime]$expiredate
        }

        Write-Information "Expiredate: $expDate"

        $ADUserParams = @{
            Name                  = $sAMAccountName
            sAMAccountName        = $sAMAccountName
            AccountPassword       = (ConvertTo-SecureString -AsPlainText $password -Force)
            path                  = $ou
            Enabled               = $true
            UserPrincipalName     = $userPrincipalName
            GivenName             = $firstname
            Surname               = $lastname
            DisplayName           = $displayName
            Description           = "Created by HelloID Form"
            Department            = $department
            Title                 = $title
            AccountExpirationDate = $expDate
        }

        $ADUserParams.Add( 'OtherAttributes', @{'EmployeeType' = "$employeeType" } )
       
        $createUser = New-ADUser @ADUserParams
        Write-Information "AD user [$sAMAccountName] created successfully"

        $adUser = Get-ADuser -Filter { UserPrincipalName -eq $userPrincipalName } | Select-Object SID
        $adUserSID = $([string]$adUser.SID)
        $Log = @{
            Action            = "CreateAccount" # optional. ENUM (undefined = default) 
            System            = "ActiveDirectory" # optional (free format text) 
            Message           = "Created account with username $userPrincipalName" # required (free format text) 
            IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = $displayName # optional (free format text) 
            TargetIdentifier  = $adUserSID # optional (free format text) 
        }
        #send result back  
        Write-Information -Tags "Audit" -MessageData $log
    }
    else {
        $adUserSID = $([string]$adUser.SID)
        $Log = @{
            Action            = "CreateAccount" # optional. ENUM (undefined = default) 
            System            = "ActiveDirectory" # optional (free format text) 
            Message           = "Account with username $userPrincipalName already exists" # required (free format text) 
            IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = $displayName # optional (free format text) 
            TargetIdentifier  = $adUserSID # optional (free format text) 
        }
        #send result back  
        Write-Information -Tags "Audit" -MessageData $log
    }
    foreach ($groupToAdd in $defaultGroups) {
        try {
            $null = Add-ADGroupMember -Identity $groupToAdd.name -Members $adUser
            Write-Information "Successfully added AD user [$sAMAccountName] to AD group $($groupToAdd.name)"
            
            $Log = @{
                Action            = "GrantMembership" # optional. ENUM (undefined = default) 
                System            = "ActiveDirectory" # optional (free format text) 
                Message           = "AD user $userPrincipalName added to group '$($groupToAdd.name)'" # required (free format text) 
                IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                TargetDisplayName = $displayName # optional (free format text) 
                TargetIdentifier  = $adUserSID # optional (free format text) 
            }
            #send result back  
            Write-Information -Tags "Audit" -MessageData $log
        }
        catch {
            Write-Error "Could not add AD user [$sAMAccountName] to AD group '$($groupToAdd.name)'. Error: $($_.Exception.Message)"
            
            $Log = @{
                Action            = "GrantMembership" # optional. ENUM (undefined = default) 
                System            = "ActiveDirectory" # optional (free format text) 
                Message           = "Failed to add AD user $userPrincipalName to group '$($groupToAdd.name)'. Error: $($_.Exception.Message)" # required (free format text) 
                IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                TargetDisplayName = $displayName # optional (free format text)
                TargetIdentifier  = $adUserSID # optional (free format text)
            }
            #send result back  
            Write-Information -Tags "Audit" -MessageData $log
        }
    }
}
catch {
    Write-Error "Error creating AD user [$sAMAccountName]. Error: $($_.Exception.Message)"
    
    $Log = @{
        Action            = "CreateAccount" # optional. ENUM (undefined = default) 
        System            = "ActiveDirectory" # optional (free format text) 
        Message           = "Error creating account with username $userPrincipalName. Error: $($_.Exception.Message)" # required (free format text) 
        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
        TargetDisplayName = $displayName # optional (free format text)
    }
    #send result back  
    Write-Information -Tags "Audit" -MessageData $log
}
