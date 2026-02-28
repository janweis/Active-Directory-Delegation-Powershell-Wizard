
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Path
)

#
# Helper functions
#

function Get-ObjectTypeGUID {
    param (
        [Parameter(Mandatory = $true, HelpMessage = "Specify the ObjectType name to look up")]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Schema", "ExtendedRights")]
        [string]$GuidStore
    )

    $propertyName = if ($GuidStore -eq "ExtendedRights") { 'rightsGuid' } else { 'ObjectGUID' }
    If ($GuidStore -eq "ExtendedRights") {
        $searchParams = @{
            SearchBase = ('CN=Extended-Rights,' + (Get-ADRootDSE).configurationNamingContext)
            LDAPFilter = "(DisplayName=$Name)"
            Properties = $propertyName
        }
    }
    else {
        $searchParams = @{
            SearchBase = (Get-ADRootDSE).schemaNamingContext
            Filter     = "lDAPDisplayName -eq '$Name'"
            Properties = $propertyName
        }
    }

    try {
        $schemaObject = Get-ADObject @searchParams

        if ($schemaObject) {
            return $schemaObject | Select-Object -ExpandProperty $propertyName -ErrorAction SilentlyContinue
        }
        else {
            return $null
        }
    }
    catch {
        return $null
    }
}


function Test-ExternalTemplateStructure {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        $Template
    )

    $isValid = $true

    if ($null -eq $Template.ID) {
        Write-Warning "Template is missing property 'ID'."
        return $false
    }

    try { $id = [int]$Template.ID } catch {
        Write-Warning "Template ID '$($Template.ID)' is not an integer."
        return $false
    }

    if (-not $Template.Template) {
        Write-Warning "Template ID $($id): property 'Template' is missing or empty."
        return $false
    }

    $rules = $Template.Template
    if (-not ($rules -is [System.Collections.IEnumerable]) -or ($rules -is [string])) { $rules = , $rules }

    foreach ($permissionTemplate in $rules) {
        
        # default value
        $isValid = $true

        #
        # Test ObjectType
        #

        if (-not $permissionTemplate.ObjectType) {
            Write-Warning "Template ID $($id): a permissionTemplate is missing 'ObjectType'."
            $isValid = $false
            continue
        }

        if ($permissionTemplate.ObjectType -notlike 'scope') {

            $objectGUID = Get-ObjectTypeGUID -Name $permissionTemplate.ObjectType -GuidStore 'Schema'
            if (-not $objectGUID) {
                Write-Warning "Template ID $($id): unknown ObjectType '$($permissionTemplate.ObjectType)'."
                $isValid = $false
                continue
            }
        }

        #
        # Test Property
        #

        if (-not $permissionTemplate.Property) {
            Write-Warning "Template ID $($id): property 'Property' is missing or empty."
            $isValid = $false
            continue
        }

        $propValid = $false
        if ($permissionTemplate.Property -eq '@') { 
            $propValid = $true 
        }
        elseif ($permissionTemplate.Property -match '^[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}$') { 
            # property is a GUID
            $propValid = $true 
        }
        else {
            
            $schemaPropGUID = Get-ObjectTypeGUID -Name $permissionTemplate.Property -GuidStore 'Schema'
            $extendedRightGUID = Get-ObjectTypeGUID -Name $permissionTemplate.Property -GuidStore 'ExtendedRights'
            if ($schemaPropGUID -or $extendedRightGUID) {
                $propValid = $true
            }
        }

        if (-not $propValid) {
            Write-Warning "Template ID $($id): unknown Property '$($permissionTemplate.Property)'. Allowed: '@', a property GUID, or (for Class 'scope') a class name."
            $isValid = $false
            continue
        }

        #
        # Test Right
        #

        if (-not $permissionTemplate.Right) {
            Write-Warning "Template ID $($id): a permissionTemplate is missing 'Right'."
            $isValid = $false
            continue
        }
    }

    return $isValid
}


#
# Main script logic
#

# Validate path
if (-not (Test-Path -LiteralPath $Path)) {
    Write-Warning "Template path '$Path' not found."
    return $loaded
}

# Determine if path is a file or directory and get JSON files accordingly
$files = @()
if ((Get-Item -LiteralPath $Path).PSIsContainer) {
    $files = Get-ChildItem -Path $Path -Filter '*.json' -File -ErrorAction SilentlyContinue | Sort-Object Name
    if ($files.Count -eq 0) {
        Write-Warning "No JSON files found in directory '$Path'."
        return $loaded
    }
}
else {
    $files = @(Get-Item -LiteralPath $Path -ErrorAction Stop)
}

# Read and parse each JSON file, handling both single object and array formats. Add SourceFile property for traceability.
foreach ($file in $files) {
    try {
        Write-Verbose -Message "Processing file: $($file.FullName)" -InformationAction Continue
        $raw = Get-Content -Path $file.FullName -Raw -ErrorAction Stop
        $json = ConvertFrom-Json -InputObject $raw -ErrorAction Stop
    }
    catch {
        Write-Warning "Failed to read/parse JSON file '$($file.FullName)': $($_.Exception.Message)"
        continue
    }

    if ($null -eq $json) {
        Write-Warning "File '$($file.FullName)' contains no JSON content — skipping."
        continue
    }

    # Handle both single object and array of objects in JSON
    $templatesInFile = @()
    if ($json -is [System.Collections.IEnumerable] -and -not ($json -is [string])) {
        $templatesInFile = $json
    }
    else {
        $templatesInFile = , $json
    }

    # Validate each template's structure and collect valid ones with source file info
    foreach ($template in $templatesInFile) {

        # Validate structure 
        if (-not (Test-ExternalTemplateStructure -Template $template)) {
            Write-Warning "[Test-DelegationTemplate] template ID $($template.ID) from '$($template.SourceFile)' failed validation and was skipped."
            continue
        }

        # Remove any existing entries with the same ID and append the external template (last-writer-wins)
        $existingCount = ($delegationTemplates | Where-Object { $_.ID -eq $template.ID }).Count
        if ($existingCount -gt 0) {
            $delegationTemplates = $delegationTemplates | Where-Object { $_.ID -ne $template.ID }
            Write-Verbose "[Test-DelegationTemplate] Removed $existingCount existing template(s) with ID $($template.ID)."
        }
    }

    Write-Verbose -Message "Finished processing file: $($file.FullName)"
}