try {
    if($blnexpdate -ne 'true'){
        $expDate = $null
    } else {
        $expDate = [datetime]$expiredate
    }
     
    Hid-Write-Status -Message "Expiredate: $expDate" -Event Information
     
     
    $ADUserParams = @{
        Name            =   $sAMAccountName
        sAMAccountName  =   $sAMAccountName
        AccountPassword =   (ConvertTo-SecureString -AsPlainText $password -Force)
        path            =   $ou
        Enabled         =   $true
        UserPrincipalName   =   $userPrincipalName
        GivenName       =   $firstname
        Surname         =   $lastname
        DisplayName     =   $displayName
        Description     =   "Created by HelloID Form"
        Department      =   $department
        Title           =   $title
        AccountExpirationDate   =   $expDate
    }
     
    $ADUserParams.Add( 'OtherAttributes', @{'EmployeeType'="$employeeType"} )
     
    New-ADUser @ADUserParams
     
    Hid-Write-Status -Message "AD user [$sAMAccountName] created successfully" -Event Success
    HID-Write-Summary -Message "AD user [$sAMAccountName] created successfully" -Event Success
     
    if(($defaultGroups -ne "[]") -and ([String]::IsNullOrEmpty($defaultGroups) -eq $false)){
        try {
            $adUser = Get-ADuser -Filter { UserPrincipalName -eq $userPrincipalName }
            $groupsToAdd = $defaultGroups
            $groupsToAddJson = $groupsToAdd | ConvertFrom-Json
             
            Add-ADPrincipalGroupMembership -Identity $adUser -MemberOf $groupsToAddJson.name -Confirm:$false
            HID-Write-Status -Message "Finished adding AD user [$sAMAccountName] to AD groups $groupsToAdd" -Event Success
            HID-Write-Summary -Message "Successfully added AD user [$sAMAccountName] to AD groups $groupsToAdd" -Event Success
        } catch {
            HID-Write-Status -Message "Could not add AD user [$sAMAccountName] to AD groups $groupsToAdd. Error: $($_.Exception.Message)" -Event Error
            HID-Write-Summary -Message "Failed to add AD user [$sAMAccountName] to AD groups $groupsToAdd" -Event Failed
        }
    }
     
} catch {
    HID-Write-Status -Message "Error creating AD user [$sAMAccountName]. Error: $($_.Exception.Message)" -Event Error
    HID-Write-Summary -Message "Error creating AD user [$sAMAccountName]" -Event Failed
}