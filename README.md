<!-- Description -->
## Description
This HelloID Service Automation Delegated Form provides AD user create functionality. The following options are available:
 1. Enter account details such as account type, name, department, jobtitle and expire date
 2. The available account names are show based on naming convention and a lookup in Active Directory
 5. The new AD user account is created in the configured OU and default AD groupmemberships are added based on the account type

## Versioning
| Version | Description | Date |
| - | - | - |
| 1.1.0   | Updated with code for SA agent | 2022/03/14  |
| 1.0.1   | Added version number and updated all-in-one script | 2021/11/04  |
| 1.0.0   | Initial release | 2020/09/01  |

<!-- TABLE OF CONTENTS -->
## Table of Contents
* [Description](#description)
* [All-in-one PowerShell setup script](#all-in-one-powershell-setup-script)
  * [Getting started](#getting-started)
* [Post-setup configuration](#post-setup-configuration)
* [Manual resources](#manual-resources)
* [Getting help](#getting-help)


## All-in-one PowerShell setup script
The PowerShell script "createform.ps1" contains a complete PowerShell script using the HelloID API to create the complete Form including user defined variables, tasks and data sources.

 _Please note that this script asumes none of the required resources do exists within HelloID. The script does not contain versioning or source control_


### Getting started
Please follow the documentation steps on [HelloID Docs](https://docs.helloid.com/hc/en-us/articles/360017556559-Service-automation-GitHub-resources) in order to setup and run the All-in one Powershell Script in your own environment.

 
## Post-setup configuration
After the all-in-one PowerShell script has run and created all the required resources. The following items need to be configured according to your own environment
 1. Update the following [user defined variables](https://docs.helloid.com/hc/en-us/articles/360014169933-How-to-Create-and-Manage-User-Defined-Variables)
<table>
  <tr><td><strong>Variable name</strong></td><td><strong>Example value</strong></td><td><strong>Description</strong></td></tr>
  <tr><td>ADuserUPNsuffix</td><td>company.local</td><td>Default UPN suffix for your domain</td></tr>
</table>
 2. Update the following values in the static data source "AD-account-generate-table-account-types-account-create" connected to the "account type" selector in the form
<table>
  <tr><td><strong>Attribute name</strong></td><td><strong>Example value</strong></td><td><strong>Description</strong></td></tr>
  <tr><td>Path</td><td>OU=Employees,OU=Users,OU=Enyoi,DC=enyoi-media,DC=local</td><td>Active Directory path for new user account</td></tr>
  <tr><td>Type</td><td>Employee</td><td>Value for new AD account's attribute "employeeType"</td></tr>
  <tr><td>Groups</td><td>[{\"Name\": \"TestGroup1\"},{\"Name\": \"TestGroup2\"}]</td><td>Json array containing objects for default AD group memberships. The AD groupname must exist in your domain</td></tr>
</table>

## Manual resources
This Delegated Form uses the following resources in order to run

### Static data source 'AD-account-generate-table-account-types-account-create'
This Static data source returns the available user types and corresponding configuration for Active Directory OU and default AD groupmemberships.

### Powershell data source 'AD-user-create-check-names'
This Powershell data source runs an Active Directory query to return available names based on configured naming convention.  

### Delegated form task 'AD-user-create'
This delegated form task will create a new AD user account based on selected available name, default groupmemberships and corresponding Active Directory container.

## Getting help
_If you need help, feel free to ask questions on our [forum](https://forum.helloid.com/forum/helloid-connectors/service-automation/532-helloid-sa-active-directory-ad-account-create)_

## HelloID Docs
The official HelloID documentation can be found at: https://docs.helloid.com/
