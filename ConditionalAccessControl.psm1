#requires -Version 3
Import-Module $PSScriptRoot\PowerShellAccessControl
Add-Type -Path $PSScriptRoot\ConditionalAceTest.cs

function Get-PacRawSecurityDescriptor {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        $InputObject,
        [switch] $Audit,
        [ROE.PowerShellAccessControl.PacSdOption] $PacSDOption
    )

    process {
        $PacSD = Get-PacSecurityDescriptor @PSBoundParameters
        New-Object System.Security.AccessControl.RawSecurityDescriptor $PacSD.Sddl
    }
}

function New-PacAceCondition {
<#
.SYNOPSIS
(Incomplete) Function to create conditional ACE condtions.

.DESCRIPTION
New-PacAceCondition is used to create ACE conditions that can be passed to the
-Condition parameter of New-PacAccessControlEntry2.

For a primer on conditional ACEs, see here: https://rohnspowershellblog.wordpress.com/2015/08/29/reading-and-creating-conditional-aces-with-powershell-kind-of/

.EXAMPLE
New-PacAceCondition -MemberOf Group1, Group2

This creates an ACE condition that is satisfied if a user is a member of both Group1 and Group2.

.EXAMPLE
New-PacAceCondition -MemberOfAny Group1, Group2

This creates an ACE condition taht is satisifed if a user is a member of either Group1 or Group2

.NOTES
This function can be extended to support more types of conditions.
#>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ParameterSetName='MemberOf')]
        [string[]] $MemberOf,
        [Parameter(Mandatory, ParameterSetName='MemberOfAny')]
        [string[]] $MemberOfAny
    )

    process {
        switch ($PSCmdlet.ParameterSetName) {

            { $_ -like '*MemberOf*' } {
                $OpByteCode = '{0}Member_of{1}' -f "$(if ($_ -like 'Device*') { 'Device_' })", "$(if ($_ -like '*Any') { '_Any' })"
                $ConditionType = [Testing.ConditionalAceUnaryCondition] 

                $Operator = New-Object Testing.ConditionalAceOperatorToken $OpByteCode
                $Condition = New-Object $ConditionType $Operator

                # Then create a composite token, which is going to contain the list of SID tokens:
                $CompositeToken = New-Object Testing.ConditionalAceCompositeToken

                # Find group SIDs (this assumes ParameterSetName is equal to the parameter)
                # It also assumes only groups are passed (there's no test for this, so a user could be passed, too)
                foreach ($Group in $PSBoundParameters[$PSCmdlet.ParameterSetName]) {
                    try {
                        $Sid = ([System.Security.Principal.NTAccount] $Group).Translate([System.Security.Principal.SecurityIdentifier])

                        $CompositeToken.Tokens.Add((New-Object Testing.ConditionalAceSecurityIdentifierToken $Sid))
                    }
                    catch {
                        Write-Warning "Unable to convert '${Group}' to security identifier: ${_}"
                    }
                }

                $Condition.Operand = New-Object Testing.ConditionalAceConditionalLiteralOperand $CompositeToken
            }

            default {
                throw "Unknown parameter set name: ${_}"
            }
        }

        return $Condition
    }
}

function Add-PacAccessControlEntry2 {
<#
.SYNOPSIS
Very primitive function for adding condtional ACEs to a security descriptor object.

.DESCRIPTION
Add-PacAccessControlEntry2 is a limited version of Add-PacAccessControlEntry that
can add conditional ACEs to discretionary access control lists. Adding to the system
access control list (audit entries) is not currently supported.

In order to use the function, you need to have a security descriptor object stored
in a variable, and that object is passed as the -InputObject to this function. You can
obtain a security descriptor object by first calling Get-Acl or Get-PacSecurityDescriptor.

After calling this function a few times on the security descriptor object, you'll need
to save it by calling Set-Acl or Set-PacSecurityDescriptor.

.EXAMPLE
$TestFile = New-Item -Path $env:temp\test_file.txt -ItemType File -Force
$SD = Get-Acl $TestFile

# Show the before:
$SD | Get-PacAccessControlEntry

# Make changes:
$SD | Add-PacAccessControlEntry2 -Principal $env:USERNAME -FolderRights FullControl -Condition (New-PacAceCondition -MemberOf Administrators, Users)
$SD | Set-Acl

# Show the after:
$TestFile | Get-PacAccessControlEntry

.EXAMPLE
$TestFolder = New-Item -Path $env:temp\test_folder -ItemType Directory -Force
$SD = Get-PacSecurityDescriptor $TestFolder

# Show the before:
$SD | Get-PacAccessControlEntry

# Make changes:
$SD | Add-PacAccessControlEntry2 -Principal $env:USERNAME -FolderRights FullControl -Condition (New-PacAceCondition -MemberOf Administrators, Users)
$SD | Set-PacSecurityDescriptor -PacSDOption (New-PacSDOption -SecurityDescriptorSections Access)

# Show the after:
$TestFolder | Get-PacAccessControlEntry

#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position=0, ValueFromPipeline)]
        [psobject] $InputObject,

        [ROE.PowerShellAccessControl.Enums.AceType] $AceType,
        
        [Parameter(Mandatory)]
        [ROE.PowerShellAccessControl.PacPrincipal] $Principal,

        [Parameter(Mandatory)]
        [Alias('FileRights','FileSystemRights')]
        [System.Security.AccessControl.FileSystemRights] $FolderRights,

        [ROE.PowerShellAccessControl.Enums.AppliesTo] $AppliesTo,

        [Parameter(Mandatory)]
        # This command exists to allow -Condition to be passed. It has less functionality than Add-PacAccessControlEntry,
        # and it's internal functionality is funky, so if you're going to use this function, you're going to have to
        # provide a conditional ACE condition :)
        [Testing.ConditionalAceCondition] $Condition
    )

    process {

        # Step 1: Is the InputObject an SD type?
        if ($InputObject -isnot [ROE.PowerShellAccessControl.AdaptedSecurityDescriptor] -and $InputObject -isnot [System.Security.AccessControl.FileSystemSecurity]) {
            throw "-InputObject must be a security descriptor object (use Get-Acl or Get-PacSecurityDescriptor)"
        }

        # Step 2: Convert InputObject to a Raw SD (neither of the valid SD objects know what to do with a conditional ACE)
        $RawSD = $InputObject | Get-PacRawSecurityDescriptor
        
        # Step 3: Create the CommonAce with the condition
        $null = $PSBoundParameters.Remove('InputObject')

        $null = $PSBoundParameters.Remove('Condition')
        $null = $PSBoundParameters.Add('OutputType', [System.Security.AccessControl.CommonAce])
        $CommonAce = New-PacAccessControlEntry @PSBoundParameters
        
        $NewAce = New-Object System.Security.AccessControl.CommonAce (
            $CommonAce.AceFlags,
            $CommonAce.AceQualifier,
            $CommonAce.AccessMask,
            $CommonAce.SecurityIdentifier,
            $true,
            $Condition.GetApplicationData()
        )

        # Just look for the first spot after explicit deny ACEs (before inherited ACEs) to preserve canonical ordering
        for ($i = 0; $i -lt $RawSD.DiscretionaryAcl.Count; $i++) {
            $CurrentAce = $RawSD.DiscretionaryAcl[$i]
            if ($CurrentAce.IsInherited -or $CurrentAce.AceQualifier.ToString() -eq "AccessAllowed") { break }
        }

        # Step 4: Add the ACE to the SD 
        $RawSD.DiscretionaryAcl.InsertAce($i, $NewAce)

        # Step 5: Modify the InputObject so it contains the new ACE 
        $InputObject.SetSecurityDescriptorSddlForm($RawSD.GetSddlForm("All"))
    }
}