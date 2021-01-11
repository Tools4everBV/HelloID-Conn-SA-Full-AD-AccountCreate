try {
    $iterationMax = 10
    $iterationStart = 1;
    $givenName = $datasource.givenName
    $middleName = $datasource.middleName
    $lastName = $datasource.lastName
    
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
    	
    	$upn = $sAMAccountName + "@" + $ADuserUPNsuffix
        
        Write-information "Searching for AD user sAMAccountName=$sAMAccountName or userPrincipalName=$upn"
        $found = Get-ADUser -Filter{sAMAccountName -eq $sAMAccountName -or userPrincipalName -eq $upn}
    
        if(@($found).count -eq 0) {
            $returnObject = @{samaccountname=$sAMAccountName; displayname=$displayName; userPrincipalName=$upn}
            Write-information "AD User sAMAccountName=$sAMAccountName or userPrincipalName=$upn not found"
            break;
        } else {
            Write-information "AD User sAMAccountName=$sAMAccountName or userPrincipalName=$upn found"
        }
    }
} catch {
    Write-error "Error generating names. Error: $($_.Exception.Message)"
}


if(-not [string]::IsNullOrEmpty($returnObject)) {
   Write-output $returnObject
}
