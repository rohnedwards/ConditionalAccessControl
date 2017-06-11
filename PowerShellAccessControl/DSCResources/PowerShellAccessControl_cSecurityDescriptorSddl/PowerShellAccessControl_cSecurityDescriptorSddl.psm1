Import-Module $PSScriptRoot\..\..\PowerShellAccessControl.psd1

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

		[parameter(Mandatory = $true)]
		[System.String]
        $Sddl,

		[System.Boolean]
		$TestInheritedAces
	)

    $Params = PrepareParams $PSBoundParameters 
    $GetSdParams = $Params.GetSdParams

    $SD = Get-PacSecurityDescriptor @GetSdParams

    # Figure out the sections that are defined in the SDDL string:
    $Sections = New-PacSecurityDescriptor -Sddl $Sddl | GetAccessControlSections

    $CurrentSddl = $SD.GetSecurityDescriptorSddlForm($Sections)
    if (-not $TestInheritedAces) { $CurrentSddl = $CurrentSddl | RemoveInheritedAces }

	$returnValue = @{
		Path = $Path
		ObjectType = $ObjectType
		Sddl = $CurrentSddl
        TestInheritedAces = $TestInheritedAces
	}

	$returnValue
}

function Set-TargetResource {
	[CmdletBinding()]
	param (
		[parameter(Mandatory = $true)]
		[System.String]
		$Path,

		[parameter(Mandatory = $true)]
		[ValidateSet("File","Directory","RegistryKey","Service","WmiNamespace")]
		[System.String]
		$ObjectType,

		[parameter(Mandatory = $true)]
		[System.String]
		$Sddl,

		[System.Boolean]
		$TestInheritedAces
	)


    $Params = PrepareParams $PSBoundParameters 
    $SetSdParams = $Params.GetSdParams
    $NewSdParams = $Params.NewSdParams

    # Can't set inherited permissions (that's up to the OS), so remove any inherited ACEs:
    Write-Verbose ("          Original Sddl = {0}" -f $NewSdParams.Sddl)
    $NewSdParams.Sddl = $NewSdParams.Sddl | RemoveInheritedAces
    Write-Verbose ("Sddl w/o Inherited ACEs = {0}" -f $NewSdParams.Sddl)

    $SourceSD = New-PacSecurityDescriptor @NewSdParams
    $Sections = GetAccessControlSections $SourceSD

    if (-not $SetSdParams.ContainsKey("PacSdOption")) {
        $SetSdParams.PacSdOption = New-PacSDOption
    }

    $SetSdParams.PacSdOption.SecurityDescriptorSections = $Sections.ToString() -as [ROE.PowerShellAccessControl.Enums.GetSecurityInformation]

    Write-Verbose ("Applying '{0}' SDDL to {1} ({2} sections)" -f $SourceSD.Sddl, $Path, $Sections)
    Set-PacSecurityDescriptor -SDObject $SourceSD @SetSdParams -Force

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
	param (
		[parameter(Mandatory = $true)]
		[System.String]
		$Path,

		[parameter(Mandatory = $true)]
		[ValidateSet("File","Directory","RegistryKey","Service","WmiNamespace")]
		[System.String]
		$ObjectType,

		[parameter(Mandatory = $true)]
		[System.String]
		$Sddl,

		[System.Boolean]
		$TestInheritedAces
	)

    $Params = PrepareParams $PSBoundParameters 
    $GetSdParams = $Params.GetSdParams
    $NewSdParams = $Params.NewSdParams

    $SourceSD = New-PacSecurityDescriptor @NewSdParams
    if ($SourceSD.GetRequestedSecurityInformation() -band [ROE.PowerShellAccessControl.Enums.SecurityInformation]::Sacl) {
        Write-Verbose "Source SDDL contains SACL information; Get-PacSecurityDescriptor will be called with -Audit switch"
        if ($GetSdParams.PacSdOption) {
            $GetSdParams.PacSdOption.SecurityDescriptorSections = [ROE.PowerShellAccessControl.Enums.GetSecurityInformation]::AllAccessAndAudit
        }
        else {
            $GetSdParams.PacSdOption = New-PacSDOption -Audit
        }
        $GetSdParams.Audit = $true
    }

    $CurrentSD = Get-PacSecurityDescriptor @GetSdParams
    $Sections = GetAccessControlSections $SourceSD

    Write-Debug "Sections: $Sections"
    $CurrentSddl = $CurrentSD.GetSecurityDescriptorSddlForm($Sections)
    $SourceSddl = $SourceSD.Sddl

    if (-not $TestInheritedAces) {
        # Remove inherited ACEs and check the Sddl strings. 
        Write-Debug "Removing inherited ACEs from SDDL strings"
        $CurrentSddl = $CurrentSddl | RemoveInheritedAces
        $SourceSddl = $SourceSD.Sddl | RemoveInheritedAces
    }

    Write-Verbose "Comparing SDDL strings:"
    Write-Verbose "    Sddl for ${Path}:"
    Write-Verbose "                 $CurrentSddl"
    Write-Verbose "    Source Sddl: $SourceSddl"
    
    $CurrentSddl -eq $SourceSddl
}

function PrepareParams {
    param(
        [hashtable] $Parameters
    )

    $GetSdParams = @{
        ErrorAction = "Stop"
    }
    $NewSdParams = @{
        ErrorAction = "Stop"
    }

    $NewSdParams.Verbose = $GetSdParams.Verbose = $false

    if ($Parameters.ContainsKey("Path")) {
        $GetSdParams.Path = $Parameters.Path
        $NewSdParams.Path = $Parameters.Path
    }

    if ($Parameters.ContainsKey("Sddl")) {
        $NewSdParams.Sddl = $Parameters.Sddl
    }

    # The $Type parameter is handled with a ValidateSet(), and the strings mentioned there don't necessarily correspond to the 
    # System.Security.AccessControl.ResourceType enumeration that Get-PacSecurityDescriptor uses. Here's where that gets translated:
    $PacCommandOptionParams = @{}
    $PacCommandOptionParams.LiteralPath = $true
    $PacCommandOptionParams.Audit = $true

    if ($Parameters.ContainsKey("ObjectType")) {
        switch ($Parameters.ObjectType) {
            
            { "File", "Directory" -contains $_ } {
                $PacCommandOptionParams.ObjectType = [System.Security.AccessControl.ResourceType]::FileObject
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
                $PacCommandOptionParams.ObjectType = [System.Security.AccessControl.ResourceType]::ProviderDefined
                $NewSdParams.IsContainer = $true

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
                    $GetSdParams.Path = "WMI Namespace: {0}" -f $Parameters.Path
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
    $GetSdParams.PacSdOption = New-PacSDOption @PacCommandOptionParams
    $NewSdParams.ObjectType = $GetSdParams.PacSdOption.ObjectType

    @{
        GetSdParams = $GetSdParams
        NewSdParams = $NewSdParams
    }
}

function GetAccessControlSections {
    
    [OutputType([System.Security.AccessControl.AccessControlSections])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline, Position=0)]
        [ROE.PowerShellAccessControl.AdaptedSecurityDescriptor] $SecurityDescriptor
    )

    process {
        $Sections = [System.Security.AccessControl.AccessControlSections]::None
        if ($SecurityDescriptor.GetRequestedSecurityInformation() -band [ROE.PowerShellAccessControl.Enums.SecurityInformation]::Owner) {
            $Sections = $Sections -bor [System.Security.AccessControl.AccessControlSections]::Owner
        }

        if ($SecurityDescriptor.GetRequestedSecurityInformation() -band [ROE.PowerShellAccessControl.Enums.SecurityInformation]::Group) {
            $Sections = $Sections -bor [System.Security.AccessControl.AccessControlSections]::Group
        }

        if ($SecurityDescriptor.GetRequestedSecurityInformation() -band [ROE.PowerShellAccessControl.Enums.SecurityInformation]::Dacl) {
            $Sections = $Sections -bor [System.Security.AccessControl.AccessControlSections]::Access
        }

        if ($SecurityDescriptor.GetRequestedSecurityInformation() -band [ROE.PowerShellAccessControl.Enums.SecurityInformation]::Sacl) {
            $Sections = $Sections -bor [System.Security.AccessControl.AccessControlSections]::Audit
        }
        
        [System.Security.AccessControl.AccessControlSections] $Sections
    }
}

function RemoveInheritedAces {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline, Position=0)]
        $InputSddl
    )

    begin {
        $InheritedAceRegEx = "\([^;]*;[^;]*ID([^;]*;){4}[^;]*\)"
    }

    process {
        $InputSddl -replace $InheritedAceRegEx
    }
}

Export-ModuleMember -Function *-TargetResource

