# Register type converter for all AuthorizationRules
[System.Security.AccessControl.FileSystemAccessRule].Assembly.GetTypes() | 
    ? { [System.Security.AccessControl.AuthorizationRule].IsAssignableFrom($_) } | ForEach-Object {
        Update-TypeData -TypeName $_ -TypeConverter ([ROE.PowerShellAccessControl.GenericAceConverter]) -ErrorAction SilentlyContinue
    }

@{
    "New-AccessControlEntry" = "New-PacAccessControlEntry"
    "Add-AccessControlEntry" = "Add-PacAccessControlEntry"
    "Get-AccessControlEntry" = "Get-PacAccessControlEntry"
    "Set-Owner" = "Set-PacOwner"
    "Remove-AccessControlEntry" = "Remove-PacAccessControlEntry"
    "Enable-AclInheritance" = "Enable-PacAclInheritance"
    "Disable-AclInheritance" = "Disable-PacAclInheritance"
    "Get-SecurityDescriptor" = "Get-PacSecurityDescriptor"
    "Set-SecurityDescriptor" = "Set-PacSecurityDescriptor"
}.GetEnumerator() | ForEach-Object {
    Set-Alias -Name $_.Key -Value $_.Value
}

Export-ModuleMember -Alias * -Cmdlet *

<#
function Get-CimInstanceFromPath {
<#
.SYNOPSIS
Converts a WMI path into a CimInstance object.
.DESCRIPTION
Get-CimInstanceFromPath takes an absolute WMI path and creates a WMI query that
Get-CimInstance takes as an argument. If everything works properly, a CimInstance
object will be returned.
.EXAMPLE
$Bios = Get-WmiObject Win32_BIOS; Get-CimInstanceFromPath -Path $Bios.__PATH
.EXAMPLE
Get-WmiObject Win32_BIOS | Get-CimInstanceFromPath
.NOTES
The function currently only works with absolute paths. It can easily be modified
to work with relative paths, too.
# >
<#
This function allows CIM objects to be represented as a string (like the WMI __PATH property). For example,
if you pass a CIM object that the module can get a security descriptor for (like a __SystemSecurity instance),
the SD's path property will include this string so that an instance of the CIM object can be obtained again.

WMI cmdlets have this functionality built-in:
$Computer = gwmi Win32_ComputerSystem
[wmi] $Computer.__PATH    # Get WMI instance from path

This function was more usefule in v1.x of this module before GetNamedSecurityInfo() and GetSecurityInfo()
windows APIs were used.
# >

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, ValueFromPipeline=$true)]
        [Alias('__PATH')]
        # WMI path (Path must be absolute path, not relative path). See __PATH 
        # property on an object returned from Get-WmiObject
        [string] $Path
    )

    process {
        if ($Path -match "^\\\\(?<computername>[^\\]*)\\(?<namespace>[^:]*):(?<classname>[^=\.]*)(?<separator>\.|(=@))(?<keyvaluepairs>.*)?$") {
            $Query = "SELECT * FROM {0}" -f $matches.classname

            switch ($matches.separator) {

                "." {
                    # Key/value pairs are in string, so add a WHERE clause
                    $Query += " WHERE {0}" -f [string]::Join(" AND ", $matches.keyvaluepairs -split ",")
                }
            }

            $GcimParams = @{
                ComputerName = $matches.computername
                Namespace = $matches.namespace
                Query = $Query
                ErrorAction = "Stop"
            }

        }
        else {
            throw "Path not in expected format!"
        }

        Get-CimInstance @GcimParams
    }
}

function Get-CimPathFromInstance {
<#
The opposite of the Get-CimInstanceFromPath. This is how a __PATH property can be computed for a CIM instance.

Like the other function, this was more useful in 1.x versions of the module. It is still used in the GetWmiObjectInfo
helper function and the Get-Win32SecurityDescriptor exposed function.
# >
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [ciminstance] $InputObject
    )

    process {
        $Keys = $InputObject.CimClass.CimClassProperties | 
            Where-Object { $_.Qualifiers.Name -contains "Key" } |
            Select-Object Name, CimType | 
            Sort-Object Name

        $KeyValuePairs = $Keys | ForEach-Object { 

            $KeyName = $_.Name
            switch -regex ($_.CimType) {

                "Boolean|.Int\d+" {
                    # No quotes surrounding value:
                    $Value = $InputObject.$KeyName
                }

                "DateTime" {
                    # Conver to WMI datetime
                    $Value = '"{0}"' -f [System.Management.ManagementDateTimeConverter]::ToDmtfDateTime($InputObject.$KeyName)
                }

                "Reference" {
                    throw "CimInstance contains a key with type 'Reference'. This isn't currenlty supported (but can be added later)"
                }

                default {
                    # Treat it like a string and cross your fingers:
                    $Value = '"{0}"'  -f ($InputObject.$KeyName -replace "`"", "\`"")
                }
            }

            "{0}={1}" -f $KeyName, $Value
        }

        if ($KeyValuePairs) { 
            $KeyValuePairsString = ".{0}" -f ($KeyValuePairs -join ",")
        }
        else {
            # This is how WMI seems to handle paths with no keys
            $KeyValuePairsString = "=@" 
        }

        "\\{0}\{1}:{2}{3}" -f $InputObject.CimSystemProperties.ServerName, 
                               ($InputObject.CimSystemProperties.Namespace -replace "/","\"), 
                               $InputObject.CimSystemProperties.ClassName, 
                               $KeyValuePairsString


    }
}
#>