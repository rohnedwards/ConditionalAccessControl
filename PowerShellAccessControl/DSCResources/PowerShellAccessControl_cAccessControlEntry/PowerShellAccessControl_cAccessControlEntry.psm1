<#
Example of where -Specific might need to be tweaked inside Get-TargetResource:

    Path       : D:\Temp\perm_test\overwritesacl
    Owner      : BUILTIN\Administrators
    Inheritance: DACL Inheritance Enabled

AceType    Principal                                             AccessMask                                            InheritedFrom                                        AppliesTo                                           
-------    ---------                                             ----------                                            -------------                                        ---------                                           
Allow      Everyone                                              FullControl                                           <not inherited>                                      O                                                   
Allow      Everyone                                              FullControl, Unknown (266403328)                      <not inherited>                                        CC CO                                             
Allow      user1                                                 Read, Synchronize                                     <not inherited>                                      O CC CO                                             
Allow      user1                                                 FullControl                                           <not inherited>                                        CC CO                                             
Allow      Administrators                                        FullControl                                           D:\Temp\                                             O CC CO                                             
Allow      CREATOR OWNER                                         FullControl                                           D:\Temp\                                               CC CO                                             
Allow      SYSTEM                                                FullControl                                           D:\Temp\                                             O CC CO                                             
Allow      Users                                                 Modify, Synchronize                                   D:\Temp\                                             O CC CO                                             

PS> Test-TargetResource D:\temp\perm_test\overwritesacl -ObjectType Directory -Principal user1 -AceType Allow -AccessMask ([System.Security.AccessControl.FileSystemRights]::FullControl) -AppliesTo "ChildContainers, ChildObjects" -Specific:$true

This will return True. There is an ACE that matches that perfectly, but, should Get-TargetResource treat -Specific as meaning that 
should be the only Principal/AceType/AccessMask combo present on the SD? If so, the extra Read ACE should cause it to fail (again, 
assuming that's what -Specific should be used for...)
#>

Import-Module $PSScriptRoot\..\..\PowerShellAccessControl.psd1

function Get-TargetResource {
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$Path,

		[parameter(Mandatory = $true)]
		[ValidateSet("File","Directory","RegistryKey","Service","WmiNamespace")]
		[System.String]
		$ObjectType,

		[parameter(Mandatory = $true)]
		[ValidateSet("Allow","Deny","Audit")]
		[System.String]
		$AceType,

		[parameter(Mandatory = $true)]
		[System.String]
		$Principal,

		[System.Int32]
		$AccessMask,

		[System.String]
		$AppliesTo,

		[System.String]
		$AuditFlags,

		[System.Boolean]
		$Specific,

		[System.Boolean]
		$TestInheritedAces

	)

    $Params = PrepareParams $PSBoundParameters
    $GetAceParams = $Params.GetAceParams
    $ModifyAceParams = $Params.ModifyAceParams # Used to get the AccessMask and AppliesTo value if ACE isn't present

    $CurrentActionString = "Getting ACEs of type '$AceType' for '$Principal' on '$Path'"
    Write-Verbose $CurrentActionString
    Write-Debug $CurrentActionString

    $MatchingAces = Get-PacAccessControlEntry @GetAceParams -Specific:$Specific
    
    if (-not $MatchingAces) {
        $returnValue = @{
            Path = $Path
            ObjectType = $ObjectType
            Ensure = "Absent"
            AceType = $AceType
            Principal = $ModifyAceParams.Principal.ToString()
            AccessMask = $ModifyAceParams.AccessMask
            AppliesTo = $ModifyAceParams.AppliesTo
            Specific = $Specific
            TestInheritedAces = $TestInheritedAces
        }

        if ($returnValue.AceType -eq "Audit") {
            $returnValue.AuditFlags = $PSBoundParameters.AuditFlags
        }

        $returnValue
    }
    else {
        $MatchingAces | ForEach-Object {
            $AceType = $_.AceType -replace "^(Access|Audit).*", '$1'
	        $returnValue = @{
		        Path = $_.Path
		        ObjectType = $ObjectType
                Ensure = "Present"
		        AceType = $AceType
		        Principal = $_.Principal
		        AccessMask = [int] $_.AccessMask
		        AppliesTo = $_.AppliesTo.AppliesToEnum.ToString()
                Specific = $Specific
                TestInheritedAces = $TestInheritedAces
	        }
        
            if ($returnValue.AceType -eq "Audit") {
                $returnValue.AuditFlags = $_.AuditFlags.ToString()
            }

            $returnValue
        }
    }
}

function Set-TargetResource {
	[CmdletBinding()]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$Path,

		[parameter(Mandatory = $true)]
		[ValidateSet("File","Directory","RegistryKey","Service","WmiNamespace")]
		[System.String]
		$ObjectType,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure = "Present",

		[parameter(Mandatory = $true)]
		[ValidateSet("Allow","Deny","Audit")]
		[System.String]
		$AceType,

		[parameter(Mandatory = $true)]
		[System.String]
		$Principal,

		[System.Int32]
		$AccessMask,

		[System.String]
		$AppliesTo,

		[System.String]
		$AuditFlags,

		[System.Boolean]
		$Specific,

		[System.Boolean]
		$TestInheritedAces

	)

    $CommandParams = @{
        Force = $true
        Apply = $true
    }

    switch ($Ensure) {

        "Present" {
            $Command = "Add-PacAccessControlEntry"
            $CommandParams.AddEvenIfAclDoesntExist = $true # Sometimes ACL might not exist. Since Get-SD is called with -Audit switch when AceType is SystemAudit, shouldn't have to worry about overwriting ACL

            if ($Specific) { $CommandParams.Overwrite = $true }
        }

        "Absent" {
            $Command = "Remove-PacAccessControlEntry"

            if ($Specific) { $CommandParams.Specific = $true }
        }

        default {
            throw 'Unknown value for $Ensure parameter'
        }
    }

    $Params = PrepareParams $PSBoundParameters
    $ModifyAceParams = $Params.ModifyAceParams # Used to get the AccessMask and AppliesTo value if ACE isn't present

    $CurrentActionString = "Calling $Command on $Path ($Principal $AceType ACE)"
    Write-Verbose $CurrentActionString
    Write-Debug $CurrentActionString
    & $Command @ModifyAceParams @CommandParams

    if ($TestInheritedAces) {
        # Inherited ACEs can be at play here. If Set-TargetResource is supposed to remove
        # access, it won't be able to remove inherited ACEs. Go ahead and call Test-TargetResource
        # to make sure it's configured correctly now; if not, write a warning:
        if (Test-TargetResource @PSBoundParameters) {

        }
        else {
            Write-Warning "TargetResource is not configured correctly after calling $Command; is this caused by inheritance?"
        }
    }
}

function Test-TargetResource {
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$Path,

		[parameter(Mandatory = $true)]
		[ValidateSet("File","Directory","RegistryKey","Service","WmiNamespace")]
		[System.String]
		$ObjectType,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure = "Present",

		[parameter(Mandatory = $true)]
		[ValidateSet("Allow","Deny","Audit")]
		[System.String]
		$AceType,

		[parameter(Mandatory = $true)]
		[System.String]
		$Principal,

		[System.Int32]
		$AccessMask,

		[System.String]
		$AppliesTo,

		[System.String]
		$AuditFlags,

		[System.Boolean]
		$Specific,

		[System.Boolean]
		$TestInheritedAces

	)

    $CurrentActionString = "Testing to see if $AceType ACE for $Principal on $Path is $Ensure"
    Write-Verbose $CurrentActionString
    Write-Debug $CurrentActionString

    if ($PSBoundParameters.ContainsKey("Ensure")) {
        $null = $PSBoundParameters.Remove("Ensure")
    }

    [bool] @(Get-TargetResource @PSBoundParameters).Where({ $_.Ensure -eq $Ensure })
}

function PrepareParams {
    param(
        [hashtable] $Parameters
    )

    $GetAceParameters = @{
        ErrorAction = "Stop"
        WarningAction = "SilentlyContinue"
    }
    $ModifyAceParameters = @{
        ErrorAction = "Stop"
    }

    $GetAceParameters.Verbose = $ModifyAceParameters.Verbose = $false

    if ($Parameters.ContainsKey("Path")) {
        $GetAceParameters.Path = $Parameters.Path
        $ModifyAceParameters.Path = $Parameters.Path
    }

    # The $Type parameter is handled with a ValidateSet(), and the strings mentioned there don't necessarily correspond to the 
    # System.Security.AccessControl.ResourceType enumeration that Get-SecurityDescriptor uses. Here's where that gets translated:
    $PacCommandOptionParams = @{}
    $PacCommandOptionParams.LiteralPath = $true
    
    if ($Parameters.AceType -eq "Audit" -and $Parameters.ContainsKey("AuditFlags")) {
        $PacCommandOptionParams.Audit = $true
    }
    elseif ($Parameters.AceType -eq "Audit" -or $Parameters.ContainsKey("AuditFlags")) {
        # If one's present, they should both be present
        throw "Audit ACEs require AceType to be 'Audit' and AuditFlags to be defined"
    }

    $AppliesToString = "Object"
    if ($Parameters.ContainsKey("ObjectType")) {
        switch ($Parameters.ObjectType) {
            
            { "File", "Directory" -contains $_ } {
                $PacCommandOptionParams.ObjectType = [System.Security.AccessControl.ResourceType]::FileObject
            }

            Directory {
                $AppliesToString = "Object, ChildContainers, ChildObjects"
            }

            RegistryKey {
                $PacCommandOptionParams.ObjectType = [System.Security.AccessControl.ResourceType]::RegistryKey
                $AppliesToString = "Object, ChildContainers"
            }

            Service {
                $PacCommandOptionParams.ObjectType = [System.Security.AccessControl.ResourceType]::Service
            }

            WmiNamespace {
                $PacCommandOptionParams.ObjectType = [System.Security.AccessControl.ResourceType]::ProviderDefined
                $AppliesToString = "Object, ChildContainers"

                <#
                 
                 Because the DSC resources allow a special "WmiNamepsace" object type, we can give the user a little
                 more leeway here. The module would normally only allow the following string paths:
                    * WMI Namespace: root/cimv2 (OptionalComputerName)
                    * \\ComputerName\root\cimv2:__SystemSecurity=@

                Because the module really only takes 'ProviderDefined' as the object type, the paths need to have
                a little more information, which is provided in the examples above. For the DSC resources, though,
                providing just the namespace is enough. So, try to see if Get-CimInstance works, and if so, assume
                user just provided the namespace and append 'WMI Namespace: ' to it so the PAC module will be happy

               #>

                try {
                    $CimInstance = Get-CimInstance -Namespace $Parameters.Path -ClassName __SystemSecurity
                    $GetAceParameters.Path = $ModifyAceParameters.Path = "WMI Namespace: {0}" -f $Parameters.Path
                }
                catch {
                    # No error; user may have provided the path in the format PAC module expects
                }
            }

            default {
                throw ('Unknown $Type parameter: {0}' -f $Parameters.Type)
            }
        }
    }
    $GetAceParameters.PacSDOption = $ModifyAceParameters.PacSDOption = New-PacSDOption @PacCommandOptionParams

    $GetAceParameters.ExcludeInherited = -not ($Parameters.TestInheritedAces)

    if ($Parameters.ContainsKey("AccessMask")) {
        $GetAceParameters.AccessMask = New-Object ROE.PowerShellAccessControl.AccessMaskAceFilter($Parameters.AccessMask, $Parameters.Specific)
        $ModifyAceParameters.AccessMask = $Parameters.AccessMask
    }
    elseif ($Parameters.Ensure -eq "Absent") {
        # No AccessMask, and we're going to ensure access isn't present. That means set AccessMask to all bits enabled:
        $ModifyAceParameters.AccessMask = [int]::MaxValue
    }
    else {
        throw "AccessMask parameter must be provided if Ensure isn't set to 'Absent'"
    }

    if ($Parameters.ContainsKey("AppliesTo")) {
        # Validate string:
        $BadAppliesTo = $Parameters.AppliesTo -split "," | foreach Trim | where { $_ -notin (echo Object, ChildContainers, ChildObjects, DirectChildrenOnly) }
        if ($BadAppliesTo -ne $null) { throw "Invalid AppliesTo value(s): $BadAppliesTo" }

        $AppliesToString = $Parameters.AppliesTo
        $GetAceParameters.AppliesTo = $AppliesToString
    }
    $ModifyAceParameters.AppliesTo = $AppliesToString

    if ($Parameters.ContainsKey("AceType")) {
        $GetAceParameters.AceType = $ModifyAceParameters.AceType = $Parameters.AceType
    }

    if ($Parameters.ContainsKey("Principal")) {
        try {
            $PacPrincipal = New-Object ROE.PowerShellAccessControl.PacPrincipal $Parameters.Principal
        }
        catch {
            $SID = $PSBoundParameters.Principal -as [System.Security.Principal.SecurityIdentifier]
            if ($SID) { $PacPrincipal = New-Object ROE.PowerShellAccessControl.PacPrincipal $SID }
            else { throw ("Unable to convert '{0}' to PacPrincipal" -f $Parameters.Principal) }
        }

        $GetAceParameters.Principal = New-Object ROE.PowerShellAccessControl.PrincipalAceFilter $PacPrincipal, $false  # Set Specific to $false
        $ModifyAceParameters.Principal = $PacPrincipal
    }

    if ($Parameters.ContainsKey("AuditFlags")) {
        # Validate string:
        $BadFlags = $Parameters.AuditFlags -split "," | foreach Trim | where { $_ -notin (echo Success, Failure) }
        if ($BadFlags -ne $null) { throw "Invalid AuditFlags: $BadFlags" }

        $GetAceParameters.AuditFlags = $ModifyAceParameters.AuditFlags = $Parameters.AuditFlags
    }


    @{
        GetAceParams = $GetAceParameters
        ModifyAceParams = $ModifyAceParameters
    }
}

Export-ModuleMember -Function *-TargetResource
