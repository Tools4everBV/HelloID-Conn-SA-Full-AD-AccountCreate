try {
    $iterationMax = 10
    $iterationStart = 1;
    $givenName = $formInput.givenName
    $middleName = $formInput.middleName
    $lastName = $formInput.lastName
     
    function Remove-StringLatinCharacters
    {
        PARAM ([string]$String)
        [Text.Encoding]::ASCII.GetString([Text.Encoding]::GetEncoding("Cyrillic").GetBytes($String))
    }
     
    for($i = $iterationStart; $i -lt $iterationMax; $i++) {
         
        $sAMAccountName = $givenName.substring(0,1) + "." + $lastName
        $displayName = $givenName + " " + $middleName + " " + $lastName
         
        if($i -eq $iterationStart) {
            $sAMAccountName = $sAMAccountName
        } else {
            $sAMAccountName = $sAMAccountName + "$i"
        }
         
        $sAMAccountName = $sAMAccountName.ToLower()
        $sAMAccountName = Remove-StringLatinCharacters $sAMAccountName
        $sAMAccountName = $sAMAccountName.trim() -replace '\s+', ''
         
        $displayName = $displayName.trim() -replace '\s+', ' '
         
        $upn = $sAMAccountName + "@" + $UPNsuffix
         
        Hid-Write-Status -Message "Searching for AD user sAMAccountName=$sAMAccountName or userPrincipalName=$upn" -Event Information
        $found = Get-ADUser -Filter{sAMAccountName -eq $sAMAccountName -or userPrincipalName -eq $upn}
     
        if(@($found).count -eq 0) {
            $returnObject = @{samaccountname=$sAMAccountName; displayname=$displayName; userPrincipalName=$upn}
            Hid-Write-Status -Message "AD User sAMAccountName=$sAMAccountName or userPrincipalName=$upn not found" -Event Information
            break;
        } else {
            Hid-Write-Status -Message "AD User sAMAccountName=$sAMAccountName or userPrincipalName=$upn found" -Event Information
        }
    }
} catch {
    HID-Write-Status -Message "Error generating names. Error: $($_.Exception.Message)" -Event Error
    HID-Write-Summary -Message "Error generating names" -Event Failed
}
 
 
if([string]::IsNullOrEmpty($returnObject)) {
    Hid-Add-TaskResult -ResultValue []
} else {
    Hid-Add-TaskResult -ResultValue $returnObject
}