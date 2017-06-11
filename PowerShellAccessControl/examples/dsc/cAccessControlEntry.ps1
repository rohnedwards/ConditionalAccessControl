# Needed for ServiceAccessRights enumeration
Import-Module PowerShellAccessControl

Configuration TestAceResource {
    param(
        [string[]] $ComputerName = "localhost"
    )

    Import-DscResource -Module PowerShellAccessControl

    $TestFolder = "C:\powershell\deleteme\dsc_test"
    $TestFile = "C:\powershell\deleteme\dsc_test\testfile"
    $TestKey = "HKLM:\SOFTWARE\Dsc_Test"

    Node $ComputerName {

        File TestFolder {
            Ensure = "Present"
            Type = "Directory"
            DestinationPath = $TestFolder
        }

        File TestFile {
            Ensure = "Present"
            DestinationPath = $TestFile
            Contents = "This is a test file"
            DependsOn = "[File]TestFolder"
        }

        cAccessControlEntry EveryoneModifyTestFolder {
            Ensure = "Present"
            Path = $TestFolder
            AceType = "Allow"
            ObjectType = "Directory"
            AccessMask = New-PacAccessMask -FolderRights Modify
            Principal = "Everyone"
            DependsOn = "[File]TestFolder"
        }

        cAccessControlEntry EveryoneDenyDeleteTestFolder {
            Ensure = "Present"
            Path = $TestFolder
            AceType = "Deny"
            ObjectType = "Directory"
            AccessMask = New-PacAccessMask -FolderRights Delete
            Principal = "Everyone"
            AppliesTo = "Object"
            DependsOn = "[File]TestFolder"
        }

        cAccessControlEntry EveryoneAuditTestFolder {
            Ensure = "Present"
            Path = $TestFolder
            AceType = "Audit"
            ObjectType = "Directory"
            AccessMask = New-PacAccessMask -FolderRights Delete
            Principal = "Everyone"
            AuditFlags = "Success, Failure"
            DependsOn = "[File]TestFolder"
        }


        cAccessControlEntry UsersFullControlTestFile {
            Ensure = "Present"
            Path = $TestFile
            AceType = "Allow"
            ObjectType = "File"
            AccessMask = New-PacAccessMask -FolderRights FullControl
            Principal = "Users"
            DependsOn = "[File]TestFile"
        }

        cAccessControlEntry EveryoneNoDeleteFile {  # Notice ObjectType
            Ensure = "Absent"
            Path = $TestFile
            AceType = "Allow"
            ObjectType = "Directory"
            AccessMask = New-PacAccessMask -FolderRights Delete
            Principal = "Everyone"
            DependsOn = "[File]TestFile"
        }

        Registry TestKey {
            Ensure = "Present"
            Key = $TestKey
            ValueName= "" 
        }

        cAccessControlEntry EveryoneFullControlTestKey {
            Ensure = "Present"
            Path = $TestKey
            ObjectType = "RegistryKey"
            AceType = "Allow"
            AccessMask = New-PacAccessMask -RegistryRights FullControl
            Principal = "Everyone"
            DependsOn = "[Registry]TestKey"
        }

        cAccessControlEntry UsersAuditSubKeysOfTestKey {
            Ensure = "Present"
            Path = $TestKey
            ObjectType = "RegistryKey"
            AceType = "Audit"
            AuditFlags = "Success,Failure"
            AccessMask = New-PacAccessMask -RegistryRights FullControl
            Principal = "Users"
            DependsOn = "[Registry]TestKey"
        }

        cAccessControlEntry UsersRestartBitsService {
            Ensure = "Present"
            Path = "bits"
            ObjectType = "Service"
            AceType = "Allow"
            AccessMask = New-PacAccessMask -ServiceRights Start, Stop
            Principal = "Users"
        }

        cAccessControlEntry EveryoneAuditFailedStartStopBitsService {
            Ensure = "Present"
            Path = "bits"
            ObjectType = "Service"
            AceType = "Audit"
            AuditFlags = "Failure"
            AccessMask = New-PacAccessMask -ServiceRights Start, Stop
            Principal = "Everyone"
        }

    }
}