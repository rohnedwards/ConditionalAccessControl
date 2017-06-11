Import-Module $PSScriptRoot\..\..\PowerShellAccessControl.psd1

# The Set-TargetResource currently overwrites anything sent to it, even if just one component is what's causing
# the test to fail. Should function be re-written to internally call Test-TargetResource for each single component?
$CsvProperties = @(
    @{Name="AceType"; E={ $_.AceType -replace "^(\Access|Audit).*", '$1' }}
    "Principal" 
    @{Name="AccessMask"; E={ [int] $_.AccessMask }}
    @{Name="AppliesTo"; E={ $_.AppliesTo.AppliesToEnum }}
    "AuditFlags"
)

function Get-TargetResource {
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param (
		[parameter(Mandatory = $true)]
		[System.String]
		$Path,

		[parameter(Mandatory = $true)]
		[ValidateSet("File","Directory","RegistryKey","Service","WmiNamespace")]
		[System.String]
		$ObjectType,

		[System.Boolean]
		$TestInheritedAces

	)

    $Params = PrepareParams $PSBoundParameters 
    $GetSdParams = $Params.GetSdParams

    $SD = Get-PacSecurityDescriptor @GetSdParams -ErrorAction Stop

    $AccessInheritance = $AuditInheritance = "Enabled"
    if ($SD.AreAccessRulesProtected) {
        $AccessInheritance = "Disabled"
    }

    if ($SD.AreAuditRulesProtected) {
        $AuditInheritance = "Disabled"
    }

    $GetAceParams = @{
        WarningAction = "SilentlyContinue"
        ExcludeInherited = -not $TestInheritedAces
    }

	$returnValue = @{
		Path = $Path
		ObjectType = $ObjectType
		Owner = $SD.Owner
		Group = $SD.Group
		Access = $SD | Get-PacAccessControlEntry -AceType Allow, Deny @GetAceParams | select $CsvProperties | ConvertTo-Csv -NoTypeInformation | Out-String
		AccessInheritance = $AccessInheritance
		Audit = $SD | Get-PacAccessControlEntry -AceType Audit @GetAceParams | select $CsvProperties | ConvertTo-Csv -NoTypeInformation | Out-String
		AuditInheritance = $AuditInheritance
        TestInheritedAces = $TestInheritedAces
	}

	$returnValue
}

function Set-TargetResource {
	[CmdletBinding()]
	param(
		[parameter(Mandatory = $true)]
		[System.String]
		$Path,

		[parameter(Mandatory = $true)]
		[ValidateSet("File","Directory","RegistryKey","Service","WmiNamespace")]
		[System.String]
		$ObjectType,

		[System.String]
		$Owner,

		[System.String]
		$Group,

		[System.String]
		$Access,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$AccessInheritance,

		[System.String]
		$Audit,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$AuditInheritance,

		[System.Boolean]
		$TestInheritedAces

	)

    $Params = PrepareParams $PSBoundParameters 
    $GetSdParams = $Params.GetSdParams
    $OptionalNewAceParams = $Params.NewAceParams

    $SD = Get-PacSecurityDescriptor @GetSdParams -ErrorAction Stop

# Sections shouldn't be needed, right? $SD will track changes...
#    $Sections = [ROE.PowerShellAccessControl.Enums.GetSecurityInformation]::None

    # Not all parameters are required, so only check sections that were provided
    foreach ($CurrentSection in "Owner","Group") {
        if ($PSBoundParameters.ContainsKey($CurrentSection)) {
            try {
                $PacPrincipal = New-Object ROE.PowerShellAccessControl.PacPrincipal $PSBoundParameters.$CurrentSection
            }
            catch {
                $SID = $PSBoundParameters.$CurrentSection -as [System.Security.Principal.SecurityIdentifier]
                if ($SID) { $PacPrincipal = New-Object ROE.PowerShellAccessControl.PacPrincipal $SID }
                else { throw ("Unable to convert '{0}' to PacPrincipal" -f $PSBoundParameters.$CurrentSection) }
            }

            Write-Verbose "Setting section $CurrentSection to $PacPrincipal"
            $SD."Set${CurrentSection}".Invoke($PacPrincipal)

#            $Sections = $Sections -bor [ROE.PowerShellAccessControl.Enums.GetSecurityInformation]::$CurrentSection
        }
    }
    foreach ($AclType in "Access", "Audit") {
        if ($PSBoundParameters.ContainsKey($AclType)) {
            Write-Verbose "Setting section $AclType"
            $DefinedAces = ConvertFrom-Csv $PSBoundParameters.$AclType | New-PacAccessControlEntry @OptionalNewAceParams

            Write-Verbose "    Removing all $AclType ACEs"
            $RemoveParams = @{ 
                "RemoveAll${AclType}Entries" = $true 
            }
            $SD | Remove-PacAccessControlEntry @RemoveParams -ErrorAction Stop

            # All explicit ACEs should have been removed
#            $CurrentSdHashTable = Get-TargetResource -Path $Path -ObjectType $ObjectType -TestInheritedAces:$TestInheritedAces
            if ($TestInheritedAces) {
                # Some of the ACEs may be inherited.
#                $CurrentAces = ConvertFrom-Csv $CurrentSdHashTable.Access  | New-PacAccessControlEntry
                $CurrentAces = $SD."Get${AclType}Rules".Invoke($false, $true, [System.Security.Principal.SecurityIdentifier]) | New-PacAccessControlEntry @OptionalNewAceParams

                $PropertiesToCheck = echo AccessControlType, Principal, { [int] $_.Rights }, AppliesTo
                $DefinedAces = Compare-Object $DefinedAces $CurrentAces -Property $PropertiesToCheck -PassThru | where SideIndicator -eq "<="
            }

            if ($DefinedAces) {
                Write-Verbose "    Adding new ACEs:"
                $DefinedAces| ForEach-Object {
                    Write-Verbose ("      {0}" -f $_.ToString())
                    $SD | Add-PacAccessControlEntry -AceObject $_ -ErrorAction Stop
                }
                $SD | Add-PacAccessControlEntry -AceObject $DefinedAces -ErrorAction Stop
            }
            else {
                Write-Verbose "    No ACEs defined"
            }
        }

        if ($PSBoundParameters.ContainsKey("${AclType}Inheritance")) {
            $Action = $PSBoundParameters["${AclType}Inheritance"] -replace "d$"
            Write-Verbose "Setting section ${AclType}Inheritance to ${Action}d"

            $Parameters = @{
                InputObject = $SD
                Force = $true     # Make it silent
                $AclType = $true
            }

            & "${Action}-PacAclInheritance" @Parameters
        }
    }

    Write-Verbose ("Applying security descriptor with the following sections: {0}" -f $SD.GetModifiedSecurityInformation())
    $SD | Set-PacSecurityDescriptor -Force

    if ($TestInheritedAces) {
        # Inherited ACEs can be at play here. Double check that all is well after calling 
        # Set-TargetResource by calling Test-TargetResource to make sure it's configured 
        # correctly now; if not, throw an error:
        if (Test-TargetResource @PSBoundParameters) {

        }
        else {
            Write-Warning "TargetResource is not configured correctly after calling Set-PacSecurityDescriptor; is this caused by inheritance?"
        }
    }
}

function Test-TargetResource {
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param(
		[parameter(Mandatory = $true)]
		[System.String]
		$Path,

		[parameter(Mandatory = $true)]
		[ValidateSet("File","Directory","RegistryKey","Service","WmiNamespace")]
		[System.String]
		$ObjectType,

		[System.String]
		$Owner,

		[System.String]
		$Group,

		[System.String]
		$Access,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$AccessInheritance,

		[System.String]
		$Audit,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$AuditInheritance,

		[System.Boolean]
		$TestInheritedAces

	)

    $Params = PrepareParams $PSBoundParameters 
    $OptionalNewAceParams = $Params.NewAceParams

    $CurrentSdHashTable = Get-TargetResource -Path $Path -ObjectType $ObjectType -TestInheritedAces:$TestInheritedAces
Write-Debug gothash
    # This will be set to false at the first failed test
    $TestsPassed = $true

    # Not all parameters are required, so only check sections that were provided
    foreach ($CurrentSection in "Owner","Group") {
        if ($PSBoundParameters.ContainsKey($CurrentSection)) {
            Write-Verbose "Checking section $CurrentSection"
            try {
                $PacPrincipal = New-Object ROE.PowerShellAccessControl.PacPrincipal $PSBoundParameters.$CurrentSection
            }
            catch {
                $SID = $PSBoundParameters.$CurrentSection -as [System.Security.Principal.SecurityIdentifier]
                if ($SID) { $PacPrincipal = New-Object ROE.PowerShellAccessControl.PacPrincipal $SID }
                else { throw ("Unable to convert '{0}' to PacPrincipal" -f $PSBoundParameters.$CurrentSection) }
            }

            if ($PacPrincipal.SecurityIdentifier -ne $CurrentSdHashTable[$CurrentSection].SecurityIdentifier) {
                Write-Verbose "    Test failed"
                $TestsPassed = $false
                break
            }
            Write-Verbose "    Test passed"
        }
    }
    foreach ($AclType in "Access", "Audit") {
        if ($PSBoundParameters.ContainsKey($AclType)) {
            Write-Verbose "Checking section $AclType"

            $CurrentAces = ConvertFrom-Csv $CurrentSdHashTable.$AclType | where { $_ } | New-PacAccessControlEntry @OptionalNewAceParams | ForEach-Object {
                [ROE.PowerShellAccessControl.GenericAceConverter]::Converter.ConvertFrom($_)
            }
            $NewAces = ConvertFrom-Csv $PSBoundParameters.$AclType | where { $_ } | New-PacAccessControlEntry @OptionalNewAceParams | ForEach-Object {
                [ROE.PowerShellAccessControl.GenericAceConverter]::Converter.ConvertFrom($_)
            }


            if ($CurrentAces -eq $null) { $CurrentAces = @() }
            if ($NewAces -eq $null) { $NewAces = @() }
Write-Debug comparing

            $AcePropertyList = echo BinaryLength, AceQualifier, IsCallback, OpaqueLength, AccessMask, SecurityIdentifier, AceType, AceFlags, InheritanceFlags, PropagationFlags, AuditFlags
            if (Compare-Object -ReferenceObject $CurrentAces -DifferenceObject $NewAces -Property $AcePropertyList -Debug:$false) {
                # Lists are different. It's possible to look to see where they are different, and only fix what's
                # wrong, but no point b/c DSC is supposed to fix this "All or Nothing".
                Write-Verbose "    Test failed"
                $TestsPassed = $false
                break  # break out of foreach block
            }
            Write-Verbose "    Test passed"
        }

        if ($PSBoundParameters.ContainsKey("${AclType}Inheritance")) {
            Write-Verbose "Checking section ${AclType}Inheritance"
            if ($PSBoundParameters["${AclType}Inheritance"] -ne $CurrentSdHashTable["${AclType}Inheritance"]) {
                Write-Verbose "    Test failed"
                $TestsPassed = $false
                break
            }
            Write-Verbose "    Test passed"
        }
    }

    $TestsPassed
}

function PrepareParams {
    param(
        [hashtable] $Parameters
    )

    $GetSdParams = @{}
    $NewSdParams = @{}
    $NewAceParams = @{}

    $NewSdParams.Verbose = $GetSdParams.Verbose = $false

    if ($Parameters.ContainsKey("Path")) {
        $GetSdParams.Path = $Parameters.Path
        $NewSdParams.Path = $Parameters.Path
    }

    if ($Parameters.ContainsKey("Sddl")) {
        $NewSdParams.Sddl = $Parameters.Sddl
    }

    # The $Type parameter is handled with a ValidateSet(), and the strings mentioned there don't necessarily correspond to the 
    # System.Security.AccessControl.ResourceType enumeration that Get-SecurityDescriptor uses. Here's where that gets translated:
    $PacCommandOptionParams = @{}
    $PacCommandOptionParams.LiteralPath = $true
    $PacCommandOptionParams.Audit = $true

    if ($Parameters.ContainsKey("ObjectType")) {
        switch ($Parameters.ObjectType) {
            
            { "File", "Directory" -contains $_ } {
                $PacCommandOptionParams.ObjectType = [System.Security.AccessControl.ResourceType]::FileObject
            }

            File {
                # New-PacAccessControlEnry is going to create ACEs that apply to Object, ChildContainers, ChildObjects
                # if the ACL definition uses a 'FolderRights' or 'FileRights' heading. That's fine for normal operation
                # b/c the module's methods/cmdlets know to strip those extra AceFlags that files can't handle, but this
                # will cause problems for testing the current state against the desired state. For that reason, hard code
                # the AppliesTo for new ACE with the ObjectType is a file
                $NewAceParams.AppliesTo = "Object"
            }

            Directory {
                $NewSdParams.IsContainer = $true
            }

            RegistryKey {
                $PacCommandOptionParams.ObjectType = [System.Security.AccessControl.ResourceType]::RegistryKey
                $NewSdParams.IsContainer = $true
            }

            Service {
                $PacCommandOptionParams.ObjectType = [System.Security.AccessControl.ResourceType]::Service
            }

            WmiNamespace {
                try {
                    $GetSdParams.Path = Get-CimInstance -Namespace $GetSdParams.Path -ClassName __SystemSecurity
                }
                catch {
                    throw "WMI Namespace path should be the path to the namespace only, e.g., 'root\cimv2'"
                }
                $NewSdParams.IsContainer = $true
            }

            default {
                throw ('Unknown $Type parameter: {0}' -f $Parameters.Type)
            }
        }
    }
    $GetSdParams.PacSdOption = New-PacSDOption @PacCommandOptionParams
    $NewSdParams.ObjectType = $GetSdParams.PacSdOption.ObjectType

    @{
        GetSdParams  = $GetSdParams
        NewSdParams  = $NewSdParams
        NewAceParams = $NewAceParams
    }
}

Export-ModuleMember -Function *-TargetResource
