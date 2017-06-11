Import-Module PowerShellAccessControl

Configuration WmiDscExample {
    param(
        [string[]] $ComputerName = "localhost"
    )

    Import-DscResource -Module PowerShellAccessControl

    Node $ComputerName {

        cAccessControlEntry UsersRemoteEnable {
            Ensure = "Present"
            Path = "ROOT\cimv2"
            AceType = "Allow"
            ObjectType = "WmiNamespace"
            AccessMask = (New-PacAccessMask -WmiNamespaceRights RemoteEnable)
            Principal = "Users"
            AppliesTo = "Object"
        }

        cAccessControlEntry EveryoneAuditRemoteEnable {
            Ensure = "Present"
            Path = "ROOT\cimv2"
            AceType = "Audit"
            AuditFlags = "Failure"
            ObjectType = "WmiNamespace"
            AccessMask = (New-PacAccessMask -WmiNamespaceRights RemoteEnable)
            Principal = "Everyone"
        }
    }
}
