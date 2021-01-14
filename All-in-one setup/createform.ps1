#HelloID variables
$script:PortalBaseUrl = "https://CUSTOMER.helloid.com"
$apiKey = "API_KEY"
$apiSecret = "API_SECRET"
$delegatedFormAccessGroupNames = @("Users", "HID_administrators")
$delegatedFormCategories = @("Active Directory", "User Management")

# Create authorization headers with HelloID API key
$pair = "$apiKey" + ":" + "$apiSecret"
$bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
$base64 = [System.Convert]::ToBase64String($bytes)
$key = "Basic $base64"
$script:headers = @{"authorization" = $Key}
# Define specific endpoint URI
$script:PortalBaseUrl = $script:PortalBaseUrl.trim("/") + "/"
 
function Write-ColorOutput($ForegroundColor) {
    $fc = $host.UI.RawUI.ForegroundColor
    $host.UI.RawUI.ForegroundColor = $ForegroundColor
    
    if ($args) {
        Write-Output $args
    } else {
        $input | Write-Output
    }

    $host.UI.RawUI.ForegroundColor = $fc
}

function Invoke-HelloIDGlobalVariable {
    param(
        [parameter(Mandatory)][String]$Name,
        [parameter(Mandatory)][String][AllowEmptyString()]$Value,
        [parameter(Mandatory)][String]$Secret
    )

    try {
        $uri = ($script:PortalBaseUrl + "api/v1/automation/variables/named/$Name")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
    
        if ([string]::IsNullOrEmpty($response.automationVariableGuid)) {
            #Create Variable
            $body = @{
                name     = $Name;
                value    = $Value;
                secret   = $Secret;
                ItemType = 0;
            }    
            $body = $body | ConvertTo-Json
    
            $uri = ($script:PortalBaseUrl + "api/v1/automation/variable")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
            $variableGuid = $response.automationVariableGuid

            Write-ColorOutput Green "Variable '$Name' created: $variableGuid"
        } else {
            $variableGuid = $response.automationVariableGuid
            Write-ColorOutput Yellow "Variable '$Name' already exists: $variableGuid"
        }
    } catch {
        Write-ColorOutput Red "Variable '$Name', message: $_"
    }
}

function Invoke-HelloIDAutomationTask {
    param(
        [parameter(Mandatory)][String]$TaskName,
        [parameter(Mandatory)][String]$UseTemplate,
        [parameter(Mandatory)][String]$AutomationContainer,
        [parameter(Mandatory)][String][AllowEmptyString()]$Variables,
        [parameter(Mandatory)][String]$PowershellScript,
        [parameter()][String][AllowEmptyString()]$ObjectGuid,
        [parameter()][String][AllowEmptyString()]$ForceCreateTask,
        [parameter(Mandatory)][Ref]$returnObject
    )
    
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/automationtasks?search=$TaskName&container=$AutomationContainer")
        $responseRaw = (Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false) 
        $response = $responseRaw | Where-Object -filter {$_.name -eq $TaskName}
    
        if([string]::IsNullOrEmpty($response.automationTaskGuid) -or $ForceCreateTask -eq $true) {
            #Create Task

            $body = @{
                name                = $TaskName;
                useTemplate         = $UseTemplate;
                powerShellScript    = $PowershellScript;
                automationContainer = $AutomationContainer;
                objectGuid          = $ObjectGuid;
                variables           = [Object[]]($Variables | ConvertFrom-Json);
            }
            $body = $body | ConvertTo-Json
    
            $uri = ($script:PortalBaseUrl +"api/v1/automationtasks/powershell")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
            $taskGuid = $response.automationTaskGuid

            Write-ColorOutput Green "Powershell task '$TaskName' created: $taskGuid"  
        } else {
            #Get TaskGUID
            $taskGuid = $response.automationTaskGuid
            Write-ColorOutput Yellow "Powershell task '$TaskName' already exists: $taskGuid"
        }
    } catch {
        Write-ColorOutput Red "Powershell task '$TaskName', message: $_"
    }

    $returnObject.Value = $taskGuid
}

function Invoke-HelloIDDatasource {
    param(
        [parameter(Mandatory)][String]$DatasourceName,
        [parameter(Mandatory)][String]$DatasourceType,
        [parameter(Mandatory)][String][AllowEmptyString()]$DatasourceModel,
        [parameter()][String][AllowEmptyString()]$DatasourceStaticValue,
        [parameter()][String][AllowEmptyString()]$DatasourcePsScript,        
        [parameter()][String][AllowEmptyString()]$DatasourceInput,
        [parameter()][String][AllowEmptyString()]$AutomationTaskGuid,
        [parameter(Mandatory)][Ref]$returnObject
    )

    $datasourceTypeName = switch($DatasourceType) { 
        "1" { "Native data source"; break} 
        "2" { "Static data source"; break} 
        "3" { "Task data source"; break} 
        "4" { "Powershell data source"; break}
    }
    
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/datasource/named/$DatasourceName")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
      
        if([string]::IsNullOrEmpty($response.dataSourceGUID)) {
            #Create DataSource
            $body = @{
                name               = $DatasourceName;
                type               = $DatasourceType;
                model              = [Object[]]($DatasourceModel | ConvertFrom-Json);
                automationTaskGUID = $AutomationTaskGuid;
                value              = [Object[]]($DatasourceStaticValue | ConvertFrom-Json);
                script             = $DatasourcePsScript;
                input              = [Object[]]($DatasourceInput | ConvertFrom-Json);
            }
            $body = $body | ConvertTo-Json
      
            $uri = ($script:PortalBaseUrl +"api/v1/datasource")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
              
            $datasourceGuid = $response.dataSourceGUID
            Write-ColorOutput Green "$datasourceTypeName '$DatasourceName' created: $datasourceGuid"
        } else {
            #Get DatasourceGUID
            $datasourceGuid = $response.dataSourceGUID
            Write-ColorOutput Yellow "$datasourceTypeName '$DatasourceName' already exists: $datasourceGuid"
        }
    } catch {
      Write-ColorOutput Red "$datasourceTypeName '$DatasourceName', message: $_"
    }

    $returnObject.Value = $datasourceGuid
}

function Invoke-HelloIDDynamicForm {
    param(
        [parameter(Mandatory)][String]$FormName,
        [parameter(Mandatory)][String]$FormSchema,
        [parameter(Mandatory)][Ref]$returnObject
    )
    
    try {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/forms/$FormName")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        } catch {
            $response = $null
        }
    
        if(([string]::IsNullOrEmpty($response.dynamicFormGUID)) -or ($response.isUpdated -eq $true)) {
            #Create Dynamic form
            $body = @{
                Name       = $FormName;
                FormSchema = $FormSchema
            }
            $body = $body | ConvertTo-Json
    
            $uri = ($script:PortalBaseUrl +"api/v1/forms")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
    
            $formGuid = $response.dynamicFormGUID
            Write-ColorOutput Green "Dynamic form '$formName' created: $formGuid"
        } else {
            $formGuid = $response.dynamicFormGUID
            Write-ColorOutput Yellow "Dynamic form '$FormName' already exists: $formGuid"
        }
    } catch {
        Write-ColorOutput Red "Dynamic form '$FormName', message: $_"
    }

    $returnObject.Value = $formGuid
}


function Invoke-HelloIDDelegatedForm {
    param(
        [parameter(Mandatory)][String]$DelegatedFormName,
        [parameter(Mandatory)][String]$DynamicFormGuid,
        [parameter()][String][AllowEmptyString()]$AccessGroups,
        [parameter()][String][AllowEmptyString()]$Categories,
        [parameter(Mandatory)][String]$UseFaIcon,
        [parameter()][String][AllowEmptyString()]$FaIcon,
        [parameter(Mandatory)][Ref]$returnObject
    )
    $delegatedFormCreated = $false
    
    try {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms/$DelegatedFormName")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        } catch {
            $response = $null
        }
    
        if([string]::IsNullOrEmpty($response.delegatedFormGUID)) {
            #Create DelegatedForm
            $body = @{
                name            = $DelegatedFormName;
                dynamicFormGUID = $DynamicFormGuid;
                isEnabled       = "True";
                accessGroups    = [Object[]]($AccessGroups | ConvertFrom-Json);
                useFaIcon       = $UseFaIcon;
                faIcon          = $FaIcon;
            }    
            $body = $body | ConvertTo-Json
    
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
    
            $delegatedFormGuid = $response.delegatedFormGUID
            Write-ColorOutput Green "Delegated form '$DelegatedFormName' created: $delegatedFormGuid"
            $delegatedFormCreated = $true

            $bodyCategories = $Categories
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms/$delegatedFormGuid/categories")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $bodyCategories
            Write-ColorOutput Green "Delegated form '$DelegatedFormName' updated with categories"
        } else {
            #Get delegatedFormGUID
            $delegatedFormGuid = $response.delegatedFormGUID
            Write-ColorOutput Yellow "Delegated form '$DelegatedFormName' already exists: $delegatedFormGuid"
        }
    } catch {
        Write-ColorOutput Red "Delegated form '$DelegatedFormName', message: $_"
    }

    $returnObject.value.guid = $delegatedFormGuid
    $returnObject.value.created = $delegatedFormCreated
}
<# Begin: HelloID Global Variables #>
$tmpValue = @'
veeken.local
'@ 
Invoke-HelloIDGlobalVariable -Name "ADuserUPNsuffix" -Value $tmpValue -Secret "False" 
<# End: HelloID Global Variables #>


<# Begin: HelloID Data sources #>
<# Begin: DataSource "AD-user-create-check-names" #>
$tmpPsScript = @'
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
'@ 
$tmpModel = @'
[{"key":"displayname","type":0},{"key":"userPrincipalName","type":0},{"key":"samaccountname","type":0}]
'@ 
$tmpInput = @'
[{"description":null,"translateDescription":false,"inputFieldType":1,"key":"givenName","type":0,"options":1},{"description":null,"translateDescription":false,"inputFieldType":1,"key":"middleName","type":0,"options":0},{"description":null,"translateDescription":false,"inputFieldType":1,"key":"lastName","type":0,"options":1}]
'@ 
$dataSourceGuid_1 = [PSCustomObject]@{} 
Invoke-HelloIDDatasource -DatasourceName "AD-user-create-check-names" -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_1) 
<# End: DataSource "AD-user-create-check-names" #>

<# Begin: DataSource "AD-ou-generate-table-create" #>
$tmpStaticValue = @'
[{"Name":"Employee","Path":"OU=Employees,OU=Users,OU=Enyoi,DC=enyoi-media,DC=local","Type":"employee","Groups":"[{\"Name\": \"TestGroup1\"},{\"Name\": \"TestGroup2\"}]","Selected":0},{"Name":"External","Path":"OU=External,OU=Users,OU=Enyoi,DC=enyoi-media,DC=local","Type":"external","Groups":"[{\"Name\": \"TestGroup2\"}]","Selected":1}]
'@ 
$tmpModel = @'
[{"key":"Type","type":0},{"key":"Path","type":0},{"key":"Selected","type":0},{"key":"Name","type":0},{"key":"Groups","type":0}]
'@ 
$dataSourceGuid_0 = [PSCustomObject]@{} 
Invoke-HelloIDDatasource -DatasourceName "AD-ou-generate-table-create" -DatasourceType "2" -DatasourceStaticValue $tmpStaticValue -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_0) 
<# End: DataSource "AD-ou-generate-table-create" #>
<# End: HelloID Data sources #>

<# Begin: Dynamic Form "AD Account - Create" #>
$tmpSchema = @"
[{"label":"Details","fields":[{"key":"ou","templateOptions":{"label":"Account type","required":true,"useObjects":false,"useDataSource":true,"useFilter":false,"options":["1111","2222","33333"],"valueField":"Path","textField":"Name","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_0","input":{"propertyInputs":[]}}},"type":"dropdown","summaryVisibility":"Show","textOrLabel":"text","requiresTemplateOptions":true},{"key":"formRow","templateOptions":{},"fieldGroup":[{"key":"givenname","templateOptions":{"label":"Givenname","placeholder":"John","required":true,"minLength":2},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true},{"key":"middlename","templateOptions":{"label":"Middle name","placeholder":"van der"},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true},{"key":"lastname","templateOptions":{"label":"Last name","placeholder":"Poel","required":true,"minLength":2},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true}],"type":"formrow","requiresTemplateOptions":true},{"key":"department","templateOptions":{"label":"Department","placeholder":"ICT"},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true},{"key":"title","templateOptions":{"label":"Job title","placeholder":"Application owner"},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true},{"key":"formRow1","templateOptions":{},"fieldGroup":[{"key":"blnExpDate","templateOptions":{"label":"Account Expires","useSwitch":true,"checkboxLabel":" yes"},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true},{"key":"expiredate","templateOptions":{"label":"Expire date","dateOnly":true},"hideExpression":"!model\[\\"blnExpDate\\"]","type":"datetime","summaryVisibility":"Show","requiresTemplateOptions":true}],"type":"formrow","requiresTemplateOptions":true},{"key":"password","templateOptions":{"label":"Password","required":true,"minLength":5},"type":"password","summaryVisibility":"Hide value","requiresTemplateOptions":true}]},{"label":"Naming","fields":[{"key":"naming","templateOptions":{"label":"Naming convention","required":true,"grid":{"columns":[{"headerName":"Displayname","field":"displayname"},{"headerName":"UserPrincipalName","field":"userPrincipalName"},{"headerName":"Samaccountname","field":"samaccountname"}],"height":300,"rowSelection":"single"},"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_1","input":{"propertyInputs":[{"propertyName":"givenName","otherFieldValue":{"otherFieldKey":"givenname"}},{"propertyName":"middleName","otherFieldValue":{"otherFieldKey":"middlename"}},{"propertyName":"lastName","otherFieldValue":{"otherFieldKey":"lastname"}}]}},"useFilter":false},"type":"grid","summaryVisibility":"Show","requiresTemplateOptions":true}]}]
"@ 

$dynamicFormGuid = [PSCustomObject]@{} 
Invoke-HelloIDDynamicForm -FormName "AD Account - Create" -FormSchema $tmpSchema  -returnObject ([Ref]$dynamicFormGuid) 
<# END: Dynamic Form #>

<# Begin: Delegated Form Access Groups and Categories #>
$delegatedFormAccessGroupGuids = @()
foreach($group in $delegatedFormAccessGroupNames) {
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/groups/$group")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        $delegatedFormAccessGroupGuid = $response.groupGuid
        $delegatedFormAccessGroupGuids += $delegatedFormAccessGroupGuid
        
        Write-ColorOutput Green "HelloID (access)group '$group' successfully found: $delegatedFormAccessGroupGuid"
    } catch {
        Write-ColorOutput Red "HelloID (access)group '$group', message: $_"
    }
}
$delegatedFormAccessGroupGuids = ($delegatedFormAccessGroupGuids | ConvertTo-Json -Compress)

$delegatedFormCategoryGuids = @()
foreach($category in $delegatedFormCategories) {
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/delegatedformcategories/$category")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        $tmpGuid = $response.delegatedFormCategoryGuid
        $delegatedFormCategoryGuids += $tmpGuid
        
        Write-ColorOutput Green "HelloID Delegated Form category '$category' successfully found: $tmpGuid"
    } catch {
        Write-ColorOutput Yellow "HelloID Delegated Form category '$category' not found"
        $body = @{
            name = @{"en" = $category};
        }
        $body = $body | ConvertTo-Json

        $uri = ($script:PortalBaseUrl +"api/v1/delegatedformcategories")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
        $tmpGuid = $response.delegatedFormCategoryGuid
        $delegatedFormCategoryGuids += $tmpGuid

        Write-ColorOutput Green "HelloID Delegated Form category '$category' successfully created: $tmpGuid"
    }
}
$delegatedFormCategoryGuids = ($delegatedFormCategoryGuids | ConvertTo-Json -Compress)
<# End: Delegated Form Access Groups and Categories #>

<# Begin: Delegated Form #>
$delegatedFormRef = [PSCustomObject]@{guid = $null; created = $null} 
Invoke-HelloIDDelegatedForm -DelegatedFormName "AD account - Create" -DynamicFormGuid $dynamicFormGuid -AccessGroups $delegatedFormAccessGroupGuids -Categories $delegatedFormCategoryGuids -UseFaIcon "True" -FaIcon "fa fa-user-plus" -returnObject ([Ref]$delegatedFormRef) 
<# End: Delegated Form #>

<# Begin: Delegated Form Task #>
if($delegatedFormRef.created -eq $true) { 
	$tmpScript = @'
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
'@; 

	$tmpVariables = @'
[{"name":"blnexpdate","value":"{{form.blnExpDate}}","secret":false,"typeConstraint":"string"},{"name":"defaultGroups","value":"{{form.ou.Groups}}","secret":false,"typeConstraint":"string"},{"name":"department","value":"{{form.department}}","secret":false,"typeConstraint":"string"},{"name":"displayname","value":"{{form.naming.displayname}}","secret":false,"typeConstraint":"string"},{"name":"employeeType","value":"{{form.ou.Type}}","secret":false,"typeConstraint":"string"},{"name":"expiredate","value":"{{form.expiredate}}","secret":false,"typeConstraint":"string"},{"name":"firstname","value":"{{form.givenname}}","secret":false,"typeConstraint":"string"},{"name":"lastname","value":"{{form.lastname}}","secret":false,"typeConstraint":"string"},{"name":"middlename","value":"{{form.middlename}}","secret":false,"typeConstraint":"string"},{"name":"ou","value":"{{form.ou.Path}}","secret":false,"typeConstraint":"string"},{"name":"password","value":"{{form.password}}","secret":false,"typeConstraint":"string"},{"name":"samaccountname","value":"{{form.naming.samaccountname}}","secret":false,"typeConstraint":"string"},{"name":"title","value":"{{form.title}}","secret":false,"typeConstraint":"string"},{"name":"userprincipalname","value":"{{form.naming.userPrincipalName}}","secret":false,"typeConstraint":"string"}]
'@ 

	$delegatedFormTaskGuid = [PSCustomObject]@{} 
	Invoke-HelloIDAutomationTask -TaskName "AD-user-create" -UseTemplate "False" -AutomationContainer "8" -Variables $tmpVariables -PowershellScript $tmpScript -ObjectGuid $delegatedFormRef.guid -ForceCreateTask $true -returnObject ([Ref]$delegatedFormTaskGuid) 
} else {
	Write-ColorOutput Yellow "Delegated form 'AD account - Create' already exists. Nothing to do with the Delegated Form task..." 
}
<# End: Delegated Form Task #>
