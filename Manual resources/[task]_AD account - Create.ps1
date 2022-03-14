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
    if($blnexpdate -ne 'true'){
    	$expDate = $null
    } else {
    	$expDate = [datetime]$expiredate
    }
    
    Write-Information "Expiredate: $expDate"
    
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

    $createUser = New-ADUser @ADUserParams
    
    Write-Information "AD user [$sAMAccountName] created successfully"

    if(-not([String]::IsNullOrEmpty($defaultGroups.Name))){
        try {
            $adUser = Get-ADuser -Filter { UserPrincipalName -eq $userPrincipalName }
            $groupsToAdd = $defaultGroups

            $addGroupMembership = Add-ADPrincipalGroupMembership -Identity $adUser -MemberOf $groupsToAdd.name -Confirm:$false
            Write-Information "Successfully added AD user [$sAMAccountName] to AD groups $($groupsToAdd | Out-String)"
        } catch {
            Write-Error "Could not add AD user [$sAMAccountName] to AD groups $($groupsToAdd.name). Error: $($_.Exception.Message)"
        }
    }
    
} catch {
    Write-Error "Error creating AD user [$sAMAccountName]. Error: $($_.Exception.Message)"
}
