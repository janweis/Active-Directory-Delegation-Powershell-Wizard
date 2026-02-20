<#
.SYNOPSIS
    Converts ACL entries from a specified AD object into a delegation template format.
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, HelpMessage = "Specify the identity to filter ACL entries (e.g., 'DOMAIN\User')")]
    [string]$Identity,

    [Parameter(Mandatory = $true, HelpMessage = "Specify the AD path to retrieve the ACL from (e.g., 'CN=Users,DC=example,DC=com')")]
    [string]$Path,

    [Parameter(HelpMessage = "Specify the description for the new template")]
    [string]$TemplateDescription,

    [Parameter(HelpMessage = "Specify the ID for the new template (default is '1000')")]
    [string]$TemplateID = "1000",

    [Parameter(Mandatory = $false, HelpMessage = "Specify the output path for the JSON file")]
    [string]$OutputPath,

    [Parameter(Mandatory = $false, HelpMessage = "Append the JSON output to the specified file if it exists")]
    [switch]$Append
)


#
# Helper functions
#

# Function to get the display name of an ObjectType GUID from the schema
function Get-ObjectTypeName {
    param (
        [Parameter(Mandatory = $true, HelpMessage = "Specify the ObjectType GUID to look up")]
        [guid]$Guid,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Schema", "ExtendedRights")]
        [string]$GuidStore
    )

    if ($Guid -eq [guid]::Empty) {
        return $null
    }

    # Determine the search parameters based on the specified GUID store
    $propertyName = if ($GuidStore -eq "ExtendedRights") { 'DisplayName' } else { 'lDAPDisplayName' }
    if ($GuidStore -eq "ExtendedRights") {
        $searchParams = @{
            SearchBase = ('CN=Extended-Rights,' + (Get-ADRootDSE).configurationNamingContext)
            LDAPFilter = "(rightsGuid=$Guid)"
            Properties = $propertyName
        }
    }
    else {
        $guidBytes = ($Guid.ToByteArray() | ForEach-Object { '\' + $_.ToString('x2') }) -join ''
        $searchParams = @{
            SearchBase = (Get-ADRootDSE).schemaNamingContext
            LDAPFilter = "(schemaIDGuid=$guidBytes)"
            Properties = $propertyName
        }
    }

    try {
        $schemaObject = Get-ADObject @searchParams

        if ($schemaObject) {
            return $schemaObject | Select-Object -ExpandProperty $propertyName -ErrorAction SilentlyContinue
        }
        else {
            Write-Warning "No schema object found for ObjectType GUID: $Guid. Using GUID as fallback."
            return $Guid
        }
    }
    catch {
        Write-Warning "Could not retrieve display name for ObjectType GUID: $Guid. Using GUID as fallback."
        return $Guid
    }
}

Import-Module ActiveDirectory

#
# Main logic
#

# Set default value for TemplateDescription if not provided
if (-not $TemplateDescription) {
    $TemplateDescription = "Generated from ACL of $Path for $Identity"
}

# Get the ACL of the specified path
$acl = Get-Acl -Path "AD:\$Path"
$filteredAccessRules = $acl.Access | Where-Object { $_.IdentityReference -like "*$Identity" }

if (-not $filteredAccessRules) {
    Write-Warning "No ACL entries found for identity '$Identity' at path '$Path'."
    return
}

# Create a new template object
$templateEntry = @{
    ID               = $TemplateID
    AppliesToClasses = 'domainDNS,organizationalUnit,container'
    Description      = $TemplateDescription
    ObjectTypes      = @()
    Template         = @()
} 

# Iterate through each access rule in the ACL
foreach ($accessRule in $filteredAccessRules) {
        
    # Extract the InheritedObjectType and ObjectType for easier reference
    $InheritedObjectType = $accessRule.InheritedObjectType.ToString()
    $ObjectType = $accessRule.ObjectType.ToString()

    # Create a permission entry for the template
    $permissionEntry = @{
        ObjectType = $null
        Property   = $null
        Right      = $accessRule.ActiveDirectoryRights.ToString()
    }

    # Define ObjectType for the permission entry based on InheritedObjectType
    if ($InheritedObjectType -eq "00000000-0000-0000-0000-000000000000") {
        $permissionEntry.ObjectType = 'scope'
    }
    else {
        $permissionEntry.ObjectType = Get-ObjectTypeName -Guid $InheritedObjectType -GuidStore "Schema"
    }

    # Add the ObjectType to the template's ObjectTypes list if it's not already included
    if (-not $templateEntry.ObjectTypes.Contains($permissionEntry.ObjectType)) {
        $templateEntry.ObjectTypes += $permissionEntry.ObjectType
    }
    
    # Define the Property for the permission entry based on ObjectType and ActiveDirectoryRights
    if ($ObjectType -eq "00000000-0000-0000-0000-000000000000") {
        $permissionEntry.Property = '@'
    }
    else {
        if ("ExtendedRight", "Self" -contains $accessRule.ActiveDirectoryRights.ToString()) {
            $permissionEntry.Property = Get-ObjectTypeName -Guid $ObjectType -GuidStore "ExtendedRights" | Select-Object -First 1
        }
        else {
            $permissionEntry.Property = Get-ObjectTypeName -Guid $ObjectType -GuidStore "Schema"

            # Backup plan: If the property name cannot be resolved and is a GUID, could be "extended write".
            if ($permissionEntry.Property -is [guid]) {
                $permissionEntry.Property = Get-ObjectTypeName -Guid $ObjectType -GuidStore "ExtendedRights" | Select-Object -First 1
            }
        }
    }

    $templateEntry.Template += $permissionEntry
}

# Convert ObjectTypes to a comma-separated string
$templateEntry.ObjectTypes = ($templateEntry.ObjectTypes | Sort-Object -Unique) -join ','

# Output the template as JSON
$json = $templateEntry | ConvertTo-Json -Depth 5

if ($OutputPath) {
    if ($Append) {
        Add-Content -Path $OutputPath -Value $json
    }
    else {
        Set-Content -Path $OutputPath -Value $json
    }
}

return $json