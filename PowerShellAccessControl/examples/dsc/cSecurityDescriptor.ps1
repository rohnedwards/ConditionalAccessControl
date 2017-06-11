Import-Module PowerShellAccessControl

Configuration TestSecurityDescriptorResource {
    param(
        [string[]] $ComputerName = "localhost"
    )

    Import-DscResource -Module PowerShellAccessControl

    $TestFolderOwner = "C:\powershell\deleteme\dsc_test_sd_owner"
    $TestFolderSacl = "C:\powershell\deleteme\dsc_test_sd_sacl"
    $TestFolderDacl = "C:\powershell\deleteme\dsc_test_sd_dacl"
    $TestKey = "HKLM:\SOFTWARE\Dsc_Test_sd"

    Node $ComputerName {

        File TestFolderOwner {
            Ensure = "Present"
            Type = "Directory"
            DestinationPath = $TestFolderOwner
        }

        File TestFolderSacl {
            Ensure = "Present"
            Type = "Directory"
            DestinationPath = $TestFolderSacl
        }

        File TestFolderDacl {
            Ensure = "Present"
            Type = "Directory"
            DestinationPath = $TestFolderDacl
        }

        cSecurityDescriptor TestFolderSdOwner {  # This sets the owner to Administrators
            Path = $TestFolderOwner
            ObjectType = "Directory"
            Owner = "Administrators"
            DependsOn = "[File]TestFolderOwner"
        }

        cSecurityDescriptor TestFolderSdSacl { 
            Path = $TestFolderSacl
            ObjectType = "Directory"
            AuditInheritance = "Enabled"
            Audit = @"
                AceType,Principal,FolderRights,AuditFlags
                Audit,Everyone,FullControl,Failure
                Audit,Users,Delete,"Success, Failure"
"@
            DependsOn = "[File]TestFolderSacl"
        }

        cSecurityDescriptor TestFolderSdDacl {
            Path = $TestFolderDacl
            ObjectType = "Directory"
            AccessInheritance = "Disabled"
            Access = @"
                AceType,Principal,FolderRights,AppliesTo
                Allow,Administrators,FullControl
                Allow,Users,"Modify, Synchronize"
                Deny,Users,Delete,Object
                Deny,Everyone,CreateDirectories,"ChildContainers, DirectChildrenOnly"
"@
            DependsOn = "[File]TestFolderDacl"
        }

        Registry TestKey {
            Ensure = "Present"
            Key = $TestKey
            ValueName= "" 
        }

        cSecurityDescriptor TestKeyFullSd { 
            Path = $TestKey
            ObjectType = "RegistryKey"
            Owner = "Administrators"
            Group = "Administrators"
            Access = @"
                Principal,RegistryRights
                Administrators,FullControl
                Users,ReadKey
"@
            Audit = @"
                AceType,Principal,RegistryRights,AuditFlags
                Audit,Everyone,FullControl,Failure
"@
            DependsOn = "[Registry]TestKey"
        }

    }
}
