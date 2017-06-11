
## Warning: Use this at your own risk. Make sure you test it on non-critical files/folders (preferably in a non-production environment) before you try to use this code.

## Overview

This module is a continuation of [this blog post](https://rohnspowershellblog.wordpress.com/2015/08/29/reading-and-creating-conditional-aces-with-powershell-kind-of/)

It's quick and dirty extension of the PowerShellAccessControl module, a binary module that eases working with security descriptors. The PAC module cannot handle conditional ACEs, so this module adds two new commands:
* New-PacAceCondition

    This command is used to create new conditions. Right now, it only supports two: MemberOf and MemberOfAny. It's used like this:
    ```
    # Create a condition that requires membership in two groups:
    New-PacAceCondition -MemberOf Group1, Group2

    # Create a condition that requires membership in either Group1 or Group2:
    New-PacAceCondition -MemberOfAny Group1, Group2
    ```

    Support for more conditions can easily be added later.

* Add-PacAccessControlEntry2
   
   This is a simpler version of Add-PacAccessControlEntry. It currently requires an in-memory security descriptor object, obtained by calling ***Get-Acl*** or ***Get-PacSecurityDescriptor***, be provided as the -InputObject.

   It adds a mandatory parameter: ***-Condition***, which is obtained by calling ***New-PacAceCondition***.

   The command is used like this:

   ```
    # Using Get-Acl and Set-Acl: 
    $TestFile = New-Item -Path $env:temp\test_file.txt -ItemType File -Force
    
    $SD = Get-Acl $TestFile
    
    # Show the before:
    $SD | Get-PacAccessControlEntry
    
    # Make changes:
    $SD | Add-PacAccessControlEntry2 -Principal $env:USERNAME -FolderRights FullControl -Condition (New-PacAceCondition -MemberOf Administrators, Users)
    $SD | Set-Acl
    
    # Show the after:
    $TestFile | Get-PacAccessControlEntry
    
    
    
    # Using Get-PacSecurityDescriptor and Set-PacSecurityDescriptor 
    $TestFolder = New-Item -Path $env:temp\test_folder -ItemType Directory -Force
    
    $SD = Get-PacSecurityDescriptor $TestFolder
    
    # Show the before:
    $SD | Get-PacAccessControlEntry
    
    # Make changes:
    $SD | Add-PacAccessControlEntry2 -Principal $env:USERNAME -FolderRights FullControl -Condition (New-PacAceCondition -MemberOf Administrators, Users)
    $SD | Set-PacSecurityDescriptor 

    # Show the after:
    $TestFolder | Get-PacAccessControlEntry
   ```

Importing the ***ConditionalAccessControl*** module automatically imports a version of the ***PowerShellAccessControl*** module.