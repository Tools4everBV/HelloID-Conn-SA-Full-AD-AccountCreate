#HelloID variables
$PortalBaseUrl = "https://CUSTOMER.helloid.com"
$apiKey = "API_KEY"
$apiSecret = "API_SECRET"
$delegatedFormAccessGroupName = "Users"
 
# Create authorization headers with HelloID API key
$pair = "$apiKey" + ":" + "$apiSecret"
$bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
$base64 = [System.Convert]::ToBase64String($bytes)
$key = "Basic $base64"
$headers = @{"authorization" = $Key}
# Define specific endpoint URI
if($PortalBaseUrl.EndsWith("/") -eq $false){
    $PortalBaseUrl = $PortalBaseUrl + "/"
}
 
$variableName = "ADuserUPNsuffix"
$variableGuid = ""
 
try {
    $uri = ($PortalBaseUrl +"api/v1/automation/variables/named/$variableName")
    $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false
 
    if([string]::IsNullOrEmpty($response.automationVariableGuid)) {
        #Create Variable
        $body = @{
            name = "$variableName";
            value = "enyoi-media.local";
            secret = "false";
            ItemType = 0;
        }
 
        $body = $body | ConvertTo-Json
 
        $uri = ($PortalBaseUrl +"api/v1/automation/variable")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false -Body $body
        $variableGuid = $response.automationVariableGuid
    } else {
        $variableGuid = $response.automationVariableGuid
    }
 
    $variableGuid
} catch {
    $_
}
 
 
 
 
$dataSourceName = "AD-ou-generate-table-create"
$dataSourceSelectOUGuid = ""
 
try {
    $uri = ($PortalBaseUrl +"api/v1/datasource/named/$dataSourceName")
    $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false
 
    if([string]::IsNullOrEmpty($response.dataSourceGUID)) {
        #Create DataSource
        $body = @{
            name = "$dataSourceName";
            type = "2";
            model = @(@{key = "Groups"; type = 0}, @{key = "Name"; type = 0}, @{key = "Path"; type = 0}, @{key = "Type"; type = 0});
            value = @(@{Name = "Employee"; Path = "OU=Employees,OU=Users,OU=Enyoi,DC=enyoi-media,DC=local"; Type = "employee"; Groups = '[{"Name": "TestGroup1"},{"Name": "TestGroup2"}]'},
            @{Name = "External"; Path = "OU=External,OU=Users,OU=Enyoi,DC=enyoi-media,DC=local"; Type = "external"; Groups = '[{"Name": "TestGroup1"}]'});
        }
        $body = $body | ConvertTo-Json
 
        $uri = ($PortalBaseUrl +"api/v1/datasource")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false -Body $body
         
        $dataSourceSelectOUGuid = $response.dataSourceGUID
    } else {
        #Get DatasourceGUID
        $dataSourceSelectOUGuid = $response.dataSourceGUID
    }
} catch {
    $_
}
 
$dataSourceSelectOUGuid
 
 
 
$taskName = "AD-user-create-check-names"
$taskCheckNamesGuid = ""
 
try {
    $uri = ($PortalBaseUrl +"api/v1/automationtasks?search=$taskName&container=1")
    $response = (Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false) | Where-Object -filter {$_.name -eq $taskName}
 
    if([string]::IsNullOrEmpty($response.automationTaskGuid)) {
        #Create Task
 
        $body = @{
            name = "$taskName";
            useTemplate = "false";
            powerShellScript = @'
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
'@;
            automationContainer = "1";
            variables = @(@{name = "UPNsuffix"; value = "{{variable.ADuserUPNsuffix}}"; typeConstraint = "string"; secret = "False"})
        }
        $body = $body | ConvertTo-Json
 
        $uri = ($PortalBaseUrl +"api/v1/automationtasks/powershell")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false -Body $body
        $taskCheckNamesGuid = $response.automationTaskGuid
 
    } else {
        #Get TaskGUID
        $taskCheckNamesGuid = $response.automationTaskGuid
    }
} catch {
    $_
}
 
$taskCheckNamesGuid
 
 
 
 
$dataSourceName = "AD-user-create-check-names"
$dataSourceCheckNamesGuid = ""
 
try {
    $uri = ($PortalBaseUrl +"api/v1/datasource/named/$dataSourceName")
    $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false
 
    if([string]::IsNullOrEmpty($response.dataSourceGUID)) {
        #Create DataSource
        $body = @{
            name = "$dataSourceName";
            type = "3";
            model = @(@{key = "displayname"; type = 0}, @{key = "samaccountname"; type = 0}, @{key = "userPrincipalName"; type = 0});
            automationTaskGUID = "$taskCheckNamesGuid";
            input = @(@{description = ""; translateDescription = "False"; inputFieldType = "1"; key = "givenName"; type = "0"; options = "1"},
            @{description = ""; translateDescription = "False"; inputFieldType = "1"; key = "lastName"; type = "0"; options = "1"},
            @{description = ""; translateDescription = "False"; inputFieldType = "1"; key = "middleName"; type = "0"; options = "0"})
        }
        $body = $body | ConvertTo-Json
 
        $uri = ($PortalBaseUrl +"api/v1/datasource")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false -Body $body
         
        $dataSourceCheckNamesGuid = $response.dataSourceGUID
    } else {
        #Get DatasourceGUID
        $dataSourceCheckNamesGuid = $response.dataSourceGUID
    }
} catch {
    $_
}
 
$dataSourceCheckNamesGuid
 
 
 
 
$formName = "AD Account - Create"
$formGuid = ""
 
try
{
    try {
        $uri = ($PortalBaseUrl +"api/v1/forms/$formName")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false
    } catch {
        $response = $null
    }
 
    if(([string]::IsNullOrEmpty($response.dynamicFormGUID)) -or ($response.isUpdated -eq $true))
    {
        #Create Dynamic form
        $form = @"
[
  {
    "label": "Details",
    "fields": [
      {
        "key": "ou",
        "templateOptions": {
          "label": "Account type",
          "required": true,
          "useObjects": false,
          "useDataSource": true,
          "useFilter": false,
          "options": [
            "1111",
            "2222",
            "33333"
          ],
          "valueField": "Path",
          "textField": "Name",
          "dataSourceConfig": {
            "dataSourceGuid": "$dataSourceSelectOUGuid",
            "input": {
              "propertyInputs": []
            }
          }
        },
        "type": "dropdown",
        "summaryVisibility": "Show",
        "textOrLabel": "text",
        "requiresTemplateOptions": true
      },
      {
        "key": "givenname",
        "templateOptions": {
          "label": "Givenname",
          "placeholder": "John",
          "required": true,
          "minLength": 2
        },
        "type": "input",
        "summaryVisibility": "Show",
        "requiresTemplateOptions": true
      },
      {
        "key": "middlename",
        "templateOptions": {
          "label": "Middle name",
          "placeholder": "van der"
        },
        "type": "input",
        "summaryVisibility": "Show",
        "requiresTemplateOptions": true
      },
      {
        "key": "lastname",
        "templateOptions": {
          "label": "Last name",
          "placeholder": "Poel",
          "required": true,
          "minLength": 2
        },
        "type": "input",
        "summaryVisibility": "Show",
        "requiresTemplateOptions": true
      },
      {
        "key": "title",
        "templateOptions": {
          "label": "Job title",
          "placeholder": "Application owner"
        },
        "type": "input",
        "summaryVisibility": "Show",
        "requiresTemplateOptions": true
      },
      {
        "key": "department",
        "templateOptions": {
          "label": "Department",
          "placeholder": "ICT"
        },
        "type": "input",
        "summaryVisibility": "Show",
        "requiresTemplateOptions": true
      },
      {
        "key": "blnExpDate",
        "templateOptions": {
          "label": "Account Expires",
          "useSwitch": true,
          "checkboxLabel": " yes"
        },
        "type": "boolean",
        "summaryVisibility": "Show",
        "requiresTemplateOptions": true
      },
      {
        "key": "expiredate",
        "templateOptions": {
          "label": "Expire date",
          "dateOnly": true
        },
        "hideExpression": "!model[\\"blnExpDate\\"]",
        "type": "datetime",
        "summaryVisibility": "Show",
        "requiresTemplateOptions": true
      },
      {
        "key": "password",
        "templateOptions": {
          "label": "Password",
          "required": true,
          "minLength": 5
        },
        "type": "password",
        "summaryVisibility": "Hide value",
        "requiresTemplateOptions": true
      }
    ]
  },
  {
    "label": "Naming",
    "fields": [
      {
        "key": "naming",
        "templateOptions": {
          "label": "Naming convention",
          "required": true,
          "grid": {
            "columns": [
              {
                "headerName": "displayName",
                "field": "displayname"
              },
              {
                "headerName": "sAMAccountname",
                "field": "samaccountname"
              },
              {
                "headerName": "userPrincipalName",
                "field": "userPrincipalName"
              }
            ],
            "height": 300,
            "rowSelection": "single"
          },
          "dataSourceConfig": {
            "dataSourceGuid": "$dataSourceCheckNamesGuid",
            "input": {
              "propertyInputs": [
                {
                  "propertyName": "givenName",
                  "otherFieldValue": {
                    "otherFieldKey": "givenname"
                  }
                },
                {
                  "propertyName": "lastName",
                  "otherFieldValue": {
                    "otherFieldKey": "lastname"
                  }
                },
                {
                  "propertyName": "middleName",
                  "otherFieldValue": {
                    "otherFieldKey": "middlename"
                  }
                }
              ]
            }
          },
          "useFilter": false
        },
        "type": "grid",
        "summaryVisibility": "Show",
        "requiresTemplateOptions": true
      }
    ]
  }
]
"@
 
        $body = @{
            Name = "$formName";
            FormSchema = $form
        }
        $body = $body | ConvertTo-Json
 
        $uri = ($PortalBaseUrl +"api/v1/forms")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false -Body $body
 
        $formGuid = $response.dynamicFormGUID
    } else {
        $formGuid = $response.dynamicFormGUID
    }
} catch {
    $_
}
 
$formGuid
 
 
 
 
$delegatedFormAccessGroupGuid = ""
 
try {
    $uri = ($PortalBaseUrl +"api/v1/groups/$delegatedFormAccessGroupName")
    $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false
    $delegatedFormAccessGroupGuid = $response.groupGuid
} catch {
    $_
}
 
$delegatedFormAccessGroupGuid
 
 
 
$delegatedFormName = "AD account - Create"
$delegatedFormGuid = ""
 
try {
    try {
        $uri = ($PortalBaseUrl +"api/v1/delegatedforms/$delegatedFormName")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false
    } catch {
        $response = $null
    }
 
    if([string]::IsNullOrEmpty($response.delegatedFormGUID)) {
        #Create DelegatedForm
        $body = @{
            name = "$delegatedFormName";
            dynamicFormGUID = "$formGuid";
            isEnabled = "True";
            accessGroups = @("$delegatedFormAccessGroupGuid");
            useFaIcon = "True";
            faIcon = "fa fa-user-plus";
        }   
 
        $body = $body | ConvertTo-Json
 
        $uri = ($PortalBaseUrl +"api/v1/delegatedforms")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false -Body $body
 
        $delegatedFormGuid = $response.delegatedFormGUID
    } else {
        #Get delegatedFormGUID
        $delegatedFormGuid = $response.delegatedFormGUID
    }
} catch {
    $_
}
 
$delegatedFormGuid
 
 
 
 
$taskActionName = "AD-user-create"
$taskActionGuid = ""
 
try {
    $uri = ($PortalBaseUrl +"api/v1/automationtasks?search=$taskActionName&container=8")
    $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false
 
    if([string]::IsNullOrEmpty($response.automationTaskGuid)) {
        #Create Task
 
        $body = @{
            name = "$taskActionName";
            useTemplate = "false";
            powerShellScript = @'
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
            automationContainer = "8";
            objectGuid = "$delegatedFormGuid";
            variables = @(@{name = "blnexpdate"; value = "{{form.blnExpDate}}"; typeConstraint = "string"; secret = "False"},
                        @{name = "defaultGroups"; value = "{{form.ou.Groups}}"; typeConstraint = "string"; secret = "False"},
                        @{name = "department"; value = "{{form.department}}"; typeConstraint = "string"; secret = "False"},
                        @{name = "displayname"; value = "{{form.naming.displayname}}"; typeConstraint = "string"; secret = "False"},
                        @{name = "employeeType"; value = "{{form.ou.Type}}"; typeConstraint = "string"; secret = "False"},
                        @{name = "expiredate"; value = "{{form.expiredate}}"; typeConstraint = "string"; secret = "False"},
                        @{name = "firstname"; value = "{{form.givenname}}"; typeConstraint = "string"; secret = "False"},
                        @{name = "lastname"; value = "{{form.lastname}}"; typeConstraint = "string"; secret = "False"},
                        @{name = "middlename"; value = "{{form.middlename}}"; typeConstraint = "string"; secret = "False"},
                        @{name = "ou"; value = "{{form.ou.Path}}"; typeConstraint = "string"; secret = "False"},
                        @{name = "password"; value = "{{form.password}}"; typeConstraint = "string"; secret = "False"},
                        @{name = "samaccountname"; value = "{{form.naming.samaccountname}}"; typeConstraint = "string"; secret = "False"},
                        @{name = "title"; value = "{{form.title}}"; typeConstraint = "string"; secret = "False"},
                        @{name = "userprincipalname"; value = "{{form.naming.userPrincipalName}}"; typeConstraint = "string"; secret = "False"});
        }
        $body = $body | ConvertTo-Json
 
        $uri = ($PortalBaseUrl +"api/v1/automationtasks/powershell")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false -Body $body
        $taskActionGuid = $response.automationTaskGuid
 
    } else {
        #Get TaskGUID
        $taskActionGuid = $response.automationTaskGuid
    }
} catch {
    $_
}
 
$taskActionGuid