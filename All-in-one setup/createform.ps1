# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

#HelloID variables
#Note: when running this script inside HelloID; portalUrl and API credentials are provided automatically (generate and save API credentials first in your admin panel!)
$portalUrl = "https://CUSTOMER.helloid.com"
$apiKey = "API_KEY"
$apiSecret = "API_SECRET"
$delegatedFormAccessGroupNames = @() #Only unique names are supported. Groups must exist!
$delegatedFormCategories = @("User Management","Active Directory") #Only unique names are supported. Categories will be created if not exists
$script:debugLogging = $false #Default value: $false. If $true, the HelloID resource GUIDs will be shown in the logging
$script:duplicateForm = $false #Default value: $false. If $true, the HelloID resource names will be changed to import a duplicate Form
$script:duplicateFormSuffix = "_tmp" #the suffix will be added to all HelloID resource names to generate a duplicate form with different resource names

#The following HelloID Global variables are used by this form. No existing HelloID global variables will be overriden only new ones are created.
#NOTE: You can also update the HelloID Global variable values afterwards in the HelloID Admin Portal: https://<CUSTOMER>.helloid.com/admin/variablelibrary
$globalHelloIDVariables = [System.Collections.Generic.List[object]]@();

#Global variable #1 >> ADgroupsSearchOU
$tmpName = @'
ADgroupsSearchOU
'@ 
$tmpValue = @'
[{ "OU": "OU=Groups,OU=Resources,DC=enyoi,DC=nl"}]
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});

#Global variable #2 >> ADusersSearchOU
$tmpName = @'
ADusersSearchOU
'@ 
$tmpValue = @'
[{ "OU": "OU=Users,OU=Resources,DC=enyoi,DC=nl"}]
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});


#make sure write-information logging is visual
$InformationPreference = "continue"

# Check for prefilled API Authorization header
if (-not [string]::IsNullOrEmpty($portalApiBasic)) {
    $script:headers = @{"authorization" = $portalApiBasic}
    Write-Information "Using prefilled API credentials"
} else {
    # Create authorization headers with HelloID API key
    $pair = "$apiKey" + ":" + "$apiSecret"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
    $base64 = [System.Convert]::ToBase64String($bytes)
    $key = "Basic $base64"
    $script:headers = @{"authorization" = $Key}
    Write-Information "Using manual API credentials"
}

# Check for prefilled PortalBaseURL
if (-not [string]::IsNullOrEmpty($portalBaseUrl)) {
    $script:PortalBaseUrl = $portalBaseUrl
    Write-Information "Using prefilled PortalURL: $script:PortalBaseUrl"
} else {
    $script:PortalBaseUrl = $portalUrl
    Write-Information "Using manual PortalURL: $script:PortalBaseUrl"
}

# Define specific endpoint URI
$script:PortalBaseUrl = $script:PortalBaseUrl.trim("/") + "/"  

# Make sure to reveive an empty array using PowerShell Core
function ConvertFrom-Json-WithEmptyArray([string]$jsonString) {
    # Running in PowerShell Core?
    if($IsCoreCLR -eq $true){
        $r = [Object[]]($jsonString | ConvertFrom-Json -NoEnumerate)
        return ,$r  # Force return value to be an array using a comma
    } else {
        $r = [Object[]]($jsonString | ConvertFrom-Json)
        return ,$r  # Force return value to be an array using a comma
    }
}

function Invoke-HelloIDGlobalVariable {
    param(
        [parameter(Mandatory)][String]$Name,
        [parameter(Mandatory)][String][AllowEmptyString()]$Value,
        [parameter(Mandatory)][String]$Secret
    )

    $Name = $Name + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

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
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl + "api/v1/automation/variable")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
            $variableGuid = $response.automationVariableGuid

            Write-Information "Variable '$Name' created$(if ($script:debugLogging -eq $true) { ": " + $variableGuid })"
        } else {
            $variableGuid = $response.automationVariableGuid
            Write-Warning "Variable '$Name' already exists$(if ($script:debugLogging -eq $true) { ": " + $variableGuid })"
        }
    } catch {
        Write-Error "Variable '$Name', message: $_"
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
    
    $TaskName = $TaskName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

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
                variables           = (ConvertFrom-Json-WithEmptyArray($Variables));
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl +"api/v1/automationtasks/powershell")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
            $taskGuid = $response.automationTaskGuid

            Write-Information "Powershell task '$TaskName' created$(if ($script:debugLogging -eq $true) { ": " + $taskGuid })"
        } else {
            #Get TaskGUID
            $taskGuid = $response.automationTaskGuid
            Write-Warning "Powershell task '$TaskName' already exists$(if ($script:debugLogging -eq $true) { ": " + $taskGuid })"
        }
    } catch {
        Write-Error "Powershell task '$TaskName', message: $_"
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

    $DatasourceName = $DatasourceName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

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
                model              = (ConvertFrom-Json-WithEmptyArray($DatasourceModel));
                automationTaskGUID = $AutomationTaskGuid;
                value              = (ConvertFrom-Json-WithEmptyArray($DatasourceStaticValue));
                script             = $DatasourcePsScript;
                input              = (ConvertFrom-Json-WithEmptyArray($DatasourceInput));
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
      
            $uri = ($script:PortalBaseUrl +"api/v1/datasource")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
              
            $datasourceGuid = $response.dataSourceGUID
            Write-Information "$datasourceTypeName '$DatasourceName' created$(if ($script:debugLogging -eq $true) { ": " + $datasourceGuid })"
        } else {
            #Get DatasourceGUID
            $datasourceGuid = $response.dataSourceGUID
            Write-Warning "$datasourceTypeName '$DatasourceName' already exists$(if ($script:debugLogging -eq $true) { ": " + $datasourceGuid })"
        }
    } catch {
      Write-Error "$datasourceTypeName '$DatasourceName', message: $_"
    }

    $returnObject.Value = $datasourceGuid
}

function Invoke-HelloIDDynamicForm {
    param(
        [parameter(Mandatory)][String]$FormName,
        [parameter(Mandatory)][String]$FormSchema,
        [parameter(Mandatory)][Ref]$returnObject
    )
    
    $FormName = $FormName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

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
                FormSchema = (ConvertFrom-Json-WithEmptyArray($FormSchema));
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl +"api/v1/forms")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
    
            $formGuid = $response.dynamicFormGUID
            Write-Information "Dynamic form '$formName' created$(if ($script:debugLogging -eq $true) { ": " + $formGuid })"
        } else {
            $formGuid = $response.dynamicFormGUID
            Write-Warning "Dynamic form '$FormName' already exists$(if ($script:debugLogging -eq $true) { ": " + $formGuid })"
        }
    } catch {
        Write-Error "Dynamic form '$FormName', message: $_"
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
        [parameter()][String][AllowEmptyString()]$task,
        [parameter(Mandatory)][Ref]$returnObject
    )
    $delegatedFormCreated = $false
    $DelegatedFormName = $DelegatedFormName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

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
                useFaIcon       = $UseFaIcon;
                faIcon          = $FaIcon;
                task            = ConvertFrom-Json -inputObject $task;
            }
            if(-not[String]::IsNullOrEmpty($AccessGroups)) { 
                $body += @{
                    accessGroups    = (ConvertFrom-Json-WithEmptyArray($AccessGroups));
                }
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
    
            $delegatedFormGuid = $response.delegatedFormGUID
            Write-Information "Delegated form '$DelegatedFormName' created$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormGuid })"
            $delegatedFormCreated = $true

            $bodyCategories = $Categories
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms/$delegatedFormGuid/categories")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $bodyCategories
            Write-Information "Delegated form '$DelegatedFormName' updated with categories"
        } else {
            #Get delegatedFormGUID
            $delegatedFormGuid = $response.delegatedFormGUID
            Write-Warning "Delegated form '$DelegatedFormName' already exists$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormGuid })"
        }
    } catch {
        Write-Error "Delegated form '$DelegatedFormName', message: $_"
    }

    $returnObject.value.guid = $delegatedFormGuid
    $returnObject.value.created = $delegatedFormCreated
}


<# Begin: HelloID Global Variables #>
foreach ($item in $globalHelloIDVariables) {
	Invoke-HelloIDGlobalVariable -Name $item.name -Value $item.value -Secret $item.secret 
}
<# End: HelloID Global Variables #>


<# Begin: HelloID Data sources #>
<# Begin: DataSource "AD-group-generate-table-members-manage-memberships" #>
$tmpPsScript = @'
try {
    $groupName = $datasource.selectedGroup.name     
    Write-information "Searching AD group [$groupName]"
     
    if(-not [String]::IsNullOrEmpty($groupName)){
        $adGroup = Get-ADgroup -Filter {Name -eq $groupName}
        Write-information "Finished searching AD group [$groupName]"
         
        $users = Get-ADGroupMember $adGroup | Where objectClass -eq "user"
        $resultCount = @($users).Count
              
        Write-information "User memberships: $resultCount"
        
        if($resultCount -gt 0){
            foreach($user in $users)
            {
                $adUser = Get-ADUser $user -properties *
                $displayValue = $adUser.displayName + " [" + $adUser.sAMAccountName + "]"
                 
                $returnObject = @{sAMAccountName="$($adUser.sAMAccountName)"; name=$displayValue}
                Write-output $returnObject
            }
        } else {
            return
        }
    }
} catch {
    Write-error "Error getting members for AD group [$groupName]. Error: $($_.Exception.Message)"
    return
}
'@ 
$tmpModel = @'
[{"key":"sAMAccountName","type":0},{"key":"name","type":0}]
'@ 
$tmpInput = @'
[{"description":null,"translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":1}]
'@ 
$dataSourceGuid_2 = [PSCustomObject]@{} 
$dataSourceGuid_2_Name = @'
AD-group-generate-table-members-manage-memberships
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_2_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_2) 
<# End: DataSource "AD-group-generate-table-members-manage-memberships" #>

<# Begin: DataSource "AD-group-generate-table-wildcard-manage-memberships" #>
$tmpPsScript = @'
try {
    $searchValue = $datasource.searchValue
    $searchQuery = "*$searchValue*"
    $searchOUs = $ADgroupsSearchOU
    
    if(-not [String]::IsNullOrEmpty($searchValue)) {
        Write-information "SearchQuery: $searchQuery"
        Write-information "SearchBase: $searchOUs"
        
        $ous = $searchOUs | ConvertFrom-Json    
        $groups = foreach($item in $ous) {
             Get-ADGroup -Filter {Name -like $searchQuery} -SearchBase $item.ou -properties *
        }
        
        $groups = $groups | Sort-Object -Property Name
        $resultCount = @($groups).Count
        Write-information "Result count: $resultCount"
    	
        if(@($groups).Count -gt 0) {
            foreach($group in $groups)
            {
                $returnObject = @{name=$group.name; description=$group.description;}
                Write-output $returnObject
            }
        } else {
            return
        }
    }
} catch {
    Write-error "Error searching AD user [$searchValue]. Error: $($_.Exception.Message)"
    return
}

'@ 
$tmpModel = @'
[{"key":"name","type":0},{"key":"description","type":0}]
'@ 
$tmpInput = @'
[{"description":null,"translateDescription":false,"inputFieldType":1,"key":"searchValue","type":0,"options":1}]
'@ 
$dataSourceGuid_0 = [PSCustomObject]@{} 
$dataSourceGuid_0_Name = @'
AD-group-generate-table-wildcard-manage-memberships
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_0_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_0) 
<# End: DataSource "AD-group-generate-table-wildcard-manage-memberships" #>

<# Begin: DataSource "AD-user-generate-table-samaccountname-manage-memberships" #>
$tmpPsScript = @'
try {
    $ous = $ADusersSearchOU | ConvertFrom-Json
    $users = foreach($item in $ous) {
        Get-ADUser -Filter {Name -like "*"} -SearchBase $item.ou -properties displayName, sAMAccountName
    }
    
    $users = $users | Sort-Object -Property DisplayName
    $resultCount = @($users).Count
    Write-information "Result count: $resultCount"
    
if($resultCount -gt 0){
        foreach($user in $users){
            $displayValue = $user.displayName + " [" + $user.sAMAccountName + "]"
            $returnObject = @{sAMAccountName=$user.sAMAccountName; name=$displayValue}
    
            Write-output $returnObject
        }
    } else {
        return
    }
} catch {
    Write-error "Error searching AD users. Error: $($_.Exception.Message)"
    return
}
'@ 
$tmpModel = @'
[{"key":"sAMAccountName","type":0},{"key":"name","type":0}]
'@ 
$tmpInput = @'
[]
'@ 
$dataSourceGuid_1 = [PSCustomObject]@{} 
$dataSourceGuid_1_Name = @'
AD-user-generate-table-samaccountname-manage-memberships
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_1_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_1) 
<# End: DataSource "AD-user-generate-table-samaccountname-manage-memberships" #>
<# End: HelloID Data sources #>

<# Begin: Dynamic Form "AD Group - Manage memberships" #>
$tmpSchema = @"
[{"label":"Select group","fields":[{"key":"searchfield","templateOptions":{"label":"Search","placeholder":""},"type":"input","summaryVisibility":"Hide element","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"gridGroups","templateOptions":{"label":"Select group","required":true,"grid":{"columns":[{"headerName":"Name","field":"name"},{"headerName":"Description","field":"description"}],"height":300,"rowSelection":"single"},"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_0","input":{"propertyInputs":[{"propertyName":"searchValue","otherFieldValue":{"otherFieldKey":"searchfield"}}]}},"useFilter":false},"type":"grid","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":true}]},{"label":"Members","fields":[{"key":"members","templateOptions":{"label":"Manage group memberships","required":false,"filterable":true,"useDataSource":true,"dualList":{"options":[{"guid":"75ea2890-88f8-4851-b202-626123054e14","Name":"Apple"},{"guid":"0607270d-83e2-4574-9894-0b70011b663f","Name":"Pear"},{"guid":"1ef6fe01-3095-4614-a6db-7c8cd416ae3b","Name":"Orange"}],"optionKeyProperty":"sAMAccountName","optionDisplayProperty":"name","labelLeft":"Available","labelRight":"Member of"},"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_1","input":{"propertyInputs":[]}},"destinationDataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_2","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"gridGroups"}}]}},"useFilter":false},"type":"duallist","summaryVisibility":"Show","sourceDataSourceIdentifierSuffix":"source-datasource","destinationDataSourceIdentifierSuffix":"destination-datasource","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false}]}]
"@ 

$dynamicFormGuid = [PSCustomObject]@{} 
$dynamicFormName = @'
AD Group - Manage memberships
'@ 
Invoke-HelloIDDynamicForm -FormName $dynamicFormName -FormSchema $tmpSchema  -returnObject ([Ref]$dynamicFormGuid) 
<# END: Dynamic Form #>

<# Begin: Delegated Form Access Groups and Categories #>
$delegatedFormAccessGroupGuids = @()
foreach($group in $delegatedFormAccessGroupNames) {
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/groups/$group")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        $delegatedFormAccessGroupGuid = $response.groupGuid
        $delegatedFormAccessGroupGuids += $delegatedFormAccessGroupGuid
        
        Write-Information "HelloID (access)group '$group' successfully found$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormAccessGroupGuid })"
    } catch {
        Write-Error "HelloID (access)group '$group', message: $_"
    }
}
if($null -ne $delegatedFormAccessGroupGuids){
    $delegatedFormAccessGroupGuids = ($delegatedFormAccessGroupGuids | Select-Object -Unique | ConvertTo-Json -Depth 100 -Compress)
}

$delegatedFormCategoryGuids = @()
foreach($category in $delegatedFormCategories) {
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/delegatedformcategories/$category")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        $tmpGuid = $response.delegatedFormCategoryGuid
        $delegatedFormCategoryGuids += $tmpGuid
        
        Write-Information "HelloID Delegated Form category '$category' successfully found$(if ($script:debugLogging -eq $true) { ": " + $tmpGuid })"
    } catch {
        Write-Warning "HelloID Delegated Form category '$category' not found"
        $body = @{
            name = @{"en" = $category};
        }
        $body = ConvertTo-Json -InputObject $body -Depth 100

        $uri = ($script:PortalBaseUrl +"api/v1/delegatedformcategories")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
        $tmpGuid = $response.delegatedFormCategoryGuid
        $delegatedFormCategoryGuids += $tmpGuid

        Write-Information "HelloID Delegated Form category '$category' successfully created$(if ($script:debugLogging -eq $true) { ": " + $tmpGuid })"
    }
}
$delegatedFormCategoryGuids = (ConvertTo-Json -InputObject $delegatedFormCategoryGuids -Depth 100 -Compress)
<# End: Delegated Form Access Groups and Categories #>

<# Begin: Delegated Form #>
$delegatedFormRef = [PSCustomObject]@{guid = $null; created = $null} 
$delegatedFormName = @'
AD Group - Manage memberships
'@
$tmpTask = @'
{"name":"AD Group - Manage memberships","script":"$VerbosePreference = \"SilentlyContinue\"\r\n$InformationPreference = \"Continue\"\r\n$WarningPreference = \"Continue\"\r\n\r\n# variables configured in form\r\n$groupName = $form.gridGroups.name\r\n$usersToAdd = $form.members.leftToRight\r\n$usersToRemove = $form.members.rightToLeft\r\n\r\ntry{\r\n    $adGroup = Get-ADgroup $groupName\r\n    Write-Information \"Found AD group [$groupName]\"\r\n}catch{\r\n    Write-Error \"Could not find AD group [$groupName]. Error: $($_.Exception.Message)\"\r\n}\r\n\r\nif($usersToAdd -ne $null){\r\n    foreach($userToAdd in $usersToAdd){\r\n        try{\r\n            $adUser = Get-ADuser $userToAdd.sAMAccountName\r\n            \r\n            $adUserDisplayName = $adUser.DisplayName\r\n            $adUserSID = $([string]$adUser.SID)\r\n\r\n            $adGroupDisplayName = $adGroup.DisplayName\r\n            $adGroupSID = $([string]$adGroup.SID)\r\n\r\n            $addMember = Add-ADGroupMember -Identity $adGroup -Members $adUser.sAMAccountName -Confirm:$false\r\n            Write-Information \"Successfully added AD user $adUserDisplayName ($adUserSID) to group $adGroupDisplayName ($adGroupSID)\"\r\n\r\n            $Log = @{\r\n                Action            = \"GrantMembership\" # optional. ENUM (undefined = default) \r\n                System            = \"ActiveDirectory\" # optional (free format text) \r\n                Message           = \"Successfully added AD user $adUserDisplayName ($adUserSID) to group $adGroupDisplayName ($adGroupSID)\" # required (free format text) \r\n                IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n                TargetDisplayName = $groupName # optional (free format text)\r\n                TargetIdentifier  = $adGroupSID # optional (free format text)\r\n            }\r\n            #send result back  \r\n            Write-Information -Tags \"Audit\" -MessageData $log\r\n        }catch{\r\n            $adGroupSID = $([string]$adGroup.SID)\r\n            $Log = @{\r\n                Action            = \"GrantMembership\" # optional. ENUM (undefined = default) \r\n                System            = \"ActiveDirectory\" # optional (free format text) \r\n                Message           = \"Failed to add AD user $adUserDisplayName ($adUserSID) to group $adGroupDisplayName ($adGroupSID). Error: $($_.Exception.Message)\" # required (free format text) \r\n                IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n                TargetDisplayName = $groupName # optional (free format text)\r\n                TargetIdentifier  = $adGroupSID # optional (free format text)\r\n            }\r\n            #send result back  \r\n            Write-Information -Tags \"Audit\" -MessageData $log\r\n\r\n            Write-Error \"Could not add AD user $adUserDisplayName ($adUserSID) to group $adGroupDisplayName ($adGroupSID). Error: $($_.Exception.Message)\"            \r\n        }\r\n    }\r\n}\r\n\r\nif($usersToRemove -ne $null){\r\n    foreach($userToRemove in $usersToRemove){\r\n        try{\r\n            $adUser = Get-ADuser $userToRemove.sAMAccountName\r\n            \r\n            $adUserDisplayName = $adUser.DisplayName\r\n            $adUserSID = $([string]$adUser.SID)\r\n\r\n            $adGroupDisplayName = $adGroup.DisplayName\r\n            $adGroupSID = $([string]$adGroup.SID)\r\n\r\n            $addMember = Remove-ADGroupMember -Identity $adGroup -Members $adUser.sAMAccountName -Confirm:$false\r\n            Write-Information \"Successfully removed AD user $adUserDisplayName ($adUserSID) from group $adGroupDisplayName ($adGroupSID)\"\r\n\r\n            $Log = @{\r\n                Action            = \"RevokeMembership\" # optional. ENUM (undefined = default) \r\n                System            = \"ActiveDirectory\" # optional (free format text) \r\n                Message           = \"Successfully removed AD user $adUserDisplayName ($adUserSID) from group $adGroupDisplayName ($adGroupSID)\" # required (free format text) \r\n                IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n                TargetDisplayName = $groupName # optional (free format text)\r\n                TargetIdentifier  = $adGroupSID # optional (free format text)\r\n            }\r\n            #send result back  \r\n            Write-Information -Tags \"Audit\" -MessageData $log\r\n        }catch{\r\n            $adGroupSID = $([string]$adGroup.SID)\r\n            $Log = @{\r\n                Action            = \"RevokeMembership\" # optional. ENUM (undefined = default) \r\n                System            = \"ActiveDirectory\" # optional (free format text) \r\n                Message           = \"Failed to remove AD user $adUserDisplayName ($adUserSID) from group $adGroupDisplayName ($adGroupSID). Error: $($_.Exception.Message)\" # required (free format text) \r\n                IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n                TargetDisplayName = $groupName # optional (free format text)\r\n                TargetIdentifier  = $adGroupSID # optional (free format text)\r\n            }\r\n            #send result back  \r\n            Write-Information -Tags \"Audit\" -MessageData $log\r\n\r\n            Write-Error \"Could not add AD user $adUserDisplayName ($adUserSID) from group $adGroupDisplayName ($adGroupSID). Error: $($_.Exception.Message)\"\r\n        }\r\n    }\r\n}","runInCloud":false}
'@ 

Invoke-HelloIDDelegatedForm -DelegatedFormName $delegatedFormName -DynamicFormGuid $dynamicFormGuid -AccessGroups $delegatedFormAccessGroupGuids -Categories $delegatedFormCategoryGuids -UseFaIcon "True" -FaIcon "fa fa-users" -task $tmpTask -returnObject ([Ref]$delegatedFormRef) 
<# End: Delegated Form #>