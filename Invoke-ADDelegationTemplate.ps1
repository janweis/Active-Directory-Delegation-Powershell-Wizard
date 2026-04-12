#requires -Version 3.0

<#
    .SYNOPSIS
    Apply delegation templates (JSON-based) to Active Directory objects or list available templates.

    .DESCRIPTION
    This script allows you to apply predefined delegation templates to Active Directory objects, granting specific permissions based
    on the rules defined in the templates. Templates are defined in external JSON files, which can be loaded from a specified path or 
    are automatically loaded from a 'templates' subdirectory. The script dynamically resolves AD schema GUIDs, supports full 
    ActiveDirectoryRights enum names, and logs applied changes for auditing and rollback purposes.

    .NOTES
    Author: Jan Weis
    Version: v1.4-prod

    .PARAMETER Identity
    Identity reference (name, SID or AD object) that will receive permissions.

    .PARAMETER Path
    Target Organizational Unit or AD object in distinguishedName format.

    .PARAMETER TemplateIDs
    One or more template IDs to apply (integer values from available templates).

    .PARAMETER TemplatePath
    Path to a JSON file or a directory containing external delegation templates. **This parameter is required** - the script contains no built-in templates; always provide `-TemplatePath` to load templates.
    Template permissionTemplate `Right` must use full ActiveDirectoryRights enum names (for example: `ReadProperty`, `WriteProperty`, `ExtendedRight`). Abbreviations (for example `RP`, `WP`, `CONTROLRIGHT`) are no longer accepted.
    If a directory is provided, all *.json files are loaded alphabetically and merged (external entries override templates by ID).

    .PARAMETER LogChanges
    Switch to enable logging of applied permission changes.

    .PARAMETER LogPath
    Path to the log file (used when -LogChanges is specified).

    .PARAMETER ShowTemplates
    Show a list of templates that can be applied.

    .PARAMETER IncludeDetails
    When used with -ShowTemplates, display permissionTemplate details and the source file.

    .PARAMETER WarnSeverity
    Severity level for warnings about properties not listed in the security template (Critical, High, Medium, Low).

    .PARAMETER DisableSecurityWarning
    Switch to disable security warnings about properties not listed in the security template.

    .EXAMPLE
    Invoke-ADDelegationTemplate -ShowTemplates -TemplatePath .\templates
    
    List all available delegation templates found in the '.\templates' directory.

    .EXAMPLE
    Invoke-ADDelegationTemplate -ShowTemplates -TemplatePath .\templates -IncludeDetails
    
    List all available delegation templates with detailed permission rules and source file information.

    .EXAMPLE
    Invoke-ADDelegationTemplate -Identity 'MySpecialGroup' -Path 'OU=Workstations,DC=contoso,DC=com' -TemplateIDs 101 -TemplatePath .\templates
    
    Applies the delegation template with ID 101 to the 'Workstations' OU, granting permissions to the 'MySpecialGroup' group.

    .EXAMPLE
    Invoke-ADDelegationTemplate -Identity 'CONTOSO\Helpdesk' -Path 'OU=Users,DC=contoso,DC=com' -TemplateIDs 101, 102 -TemplatePath .\templates -LogChanges -LogPath C:\Logs\Delegation.log
    
    Applies templates 101 and 102 to the 'Users' OU for the 'Helpdesk' group, and logs all applied changes to 'C:\Logs\Delegation.log'.
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory, ParameterSetName = 'DoTheMagic')]
    [string]$Identity,

    [Parameter(Mandatory, ParameterSetName = 'DoTheMagic')]
    [string]$Path,

    [Parameter(Mandatory, ParameterSetName = 'DoTheMagic')]
    [int[]]$TemplateIDs,

    [Parameter()]
    [string]$TemplatePath,
            
    [Parameter(ParameterSetName = 'DoTheMagic')]
    [switch]$LogChanges,

    [Parameter(ParameterSetName = 'DoTheMagic')]
    [string]$LogPath,

    [Parameter(Mandatory, ParameterSetName = 'Viewer')]
    [switch]$ShowTemplates,
            
    [Parameter(ParameterSetName = 'Viewer')]
    [switch]$IncludeDetails,

    [ValidateSet('Critical', 'High', 'Medium', 'Low')]
    [string]$WarnSeverity = 'Medium',

    [switch]$DisableSecurityWarning = $false
)
begin {
    Write-Verbose -Message '[Invoke-ADDelegationTemplate] START'


    #
    # Configuration and Initialization
    #
            
    # Auto-load templates from the 'templates' subdirectory by default if no TemplatePath is provided. This allows the script to 
    # be used with built-in templates without requiring the user to specify a path, while still supporting external templates when needed.
    $AutoTemplatesLoader = $true 
            
    # If no TemplatePath is provided, attempt to load templates from the 'templates' subdirectory relative to the script location. 
    # This allows for a default set of templates to be included with the script while still supporting external templates when needed.
    $AutoTemplatesPath = Join-Path -Path $PSScriptRoot -ChildPath 'templates'
    $AutoSecurityTemplatePath = Join-Path -Path $PSScriptRoot -ChildPath 'security'

    # Templates
    $delegationTemplates = @()
    $securityTemplateList = @()


    #
    # Functions
    #

    # Define a mapping of warning severity levels to numeric scores for comparison purposes. 
    # Get the numeric severity score for the specified WarnSeverity level
    $warnSeverityMap = @{'Critical' = 4; 'High' = 3; 'Medium' = 2; 'Low' = 1 }
    $warnSeverityScore = $warnSeverityMap[$WarnSeverity]

    # Get ObjectType GUID from Schema or Extended Rights or schema class name
    function Get-ObjectTypeGUID {
        param (
            [Parameter(Mandatory = $true, HelpMessage = "Specify the ObjectType name to look up")]
            [string]$Name,

            [Parameter(Mandatory = $true)]
            [ValidateSet("Schema", "ExtendedRights")]
            [string]$GuidStore
        )

        # Setup search parameters based on the type of GUID being looked up (schema class vs extended right)
        $propertyName = if ($GuidStore -eq "ExtendedRights") { 'rightsGuid' } else { 'schemaIDGuid' }
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
                LDAPFilter = "(lDAPDisplayName=$Name)"
                Properties = $propertyName
            }
        }

        # Let's try to retrieve the schema object and extract the GUID permissionsOrPropertiesItem. 
        try {
            $schemaObject = Get-ADObject @searchParams

            if ($schemaObject) {
                return ($schemaObject.$propertyName -as [Guid])
            }
            else {
                Write-Warning "[Get-ObjectTypeGUID] No schema object found for ObjectType name: $Name."
                return $null
            }
        }
        catch {
            Write-Warning "[Get-ObjectTypeGUID] Could not retrieve ObjectType GUID for name: $Name."
            return $null
        }
    }

    # Import the external templates from JSON file(s) and return an array of template objects with SourceFile permissionsOrPropertiesItem for traceability
    function Import-ExternalTemplates {
        param(
            [Parameter(Mandatory = $true)]
            [string]$Path
        )

        $loaded = @()

        # Validate path
        if (-not (Test-Path -LiteralPath $Path)) {
            Write-Warning "[Import-ExternalTemplates] Template path '$Path' not found."
            return $loaded
        }

        # Determine if path is a file or directory and get JSON files accordingly
        $files = @()
        if ((Get-Item -LiteralPath $Path).PSIsContainer) {
            $files = Get-ChildItem -Path $Path -Filter '*.json' -File -ErrorAction SilentlyContinue | Sort-Object Name
            if ($files.Count -eq 0) {
                Write-Warning "[Import-ExternalTemplates] No JSON files found in directory '$Path'."
                return $loaded
            }
        }
        else {
            $files = @(Get-Item -LiteralPath $Path -ErrorAction Stop)
        }

        # Read and parse each JSON file, handling both single object and array formats. Add SourceFile permissionsOrPropertiesItem for traceability.
        foreach ($file in $files) {
            Write-Verbose "[Import-ExternalTemplates] Processing template file '$($file.FullName)'"
                
            try {
                $raw = Get-Content -Path $file.FullName -Raw -ErrorAction Stop
                $json = ConvertFrom-Json -InputObject $raw -ErrorAction Stop
            }
            catch {
                Write-Warning "[Import-ExternalTemplates] Failed to read/parse JSON file '$($file.FullName)': $($_.Exception.Message)"
                continue
            }

            if ($null -eq $json) {
                Write-Warning "[Import-ExternalTemplates] File '$($file.FullName)' contains no JSON content - skipping."
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

            # Validate and flatten templates, adding SourceFile permissionsOrPropertiesItem. Also check for duplicate IDs 
            # within the same file to avoid conflicts.
            $seenIds = @{}
            foreach ($template in $templatesInFile) {
                if ($null -eq $template.ID) {
                    Write-Warning "[Import-ExternalTemplates] Template in file '$($file.Name)' missing permissionsOrPropertiesItem 'ID' - skipping."
                    continue
                }

                try { $tid = [int]$template.ID } catch {
                    Write-Warning "[Import-ExternalTemplates] Template ID '$($template.ID)' in file '$($file.Name)' is not an integer - skipping."
                    continue
                }

                if ($seenIds.ContainsKey($tid)) {
                    Write-Warning "[Import-ExternalTemplates] Duplicate template ID $tid in file '$($file.Name)' - skipping duplicate."
                    continue
                }

                $seenIds[$tid] = $true

                $obj = [PSCustomObject]@{
                    ID          = $tid
                    Category    = $template.Category
                    ObjectClass = $template.ObjectClass
                    ObjectTypes = $template.ObjectTypes
                    Description = $template.Description
                    AppliesTo   = $template.AppliesTo
                    Template    = $template.Template
                    SourceFile  = $file.Name
                }

                $loaded += $obj
            }
        }

        return $loaded
    }

    # Import security templates from JSON file and return an array of template objects with SourceFile permissionsOrPropertiesItem for traceability
    function Import-SecurityTemplate {
        param (
            [Parameter(Mandatory)]
            [string]$Path
        )

        # File name is fixed to 'security-reference.json' for security templates
        $securityFileName = 'security-reference.json'
        $fullPath = Join-Path -Path $Path -ChildPath $securityFileName

        # Validate file existence
        if (-not (Test-Path -LiteralPath $fullPath)) {
            Write-Verbose "[Import-SecurityTemplate] Security template file '$fullPath' not found."
            return @()
        }

        # Read and parse the JSON file
        try {
            $raw = Get-Content -Path $fullPath -Raw -ErrorAction Stop
            $json = ConvertFrom-Json -InputObject $raw -ErrorAction Stop

            return $json
        }
        catch {
            Write-Warning "[Import-SecurityTemplate] Failed to read/parse security template JSON file '$fullPath': $($_.Exception.Message)"
        }

        return @()
    }

    # Find a security template reference for a given property and object type, returning context-specific details if available.
    function Find-SecurityTemplateReference {
        param (
            [Parameter(Mandatory)]
            [string]$Property,

            [Parameter(Mandatory)]
            [string]$ObjectType
        )

        if ($securityTemplateList) {
            foreach ($reference in $securityTemplateList.references) {
                if ($reference.attribute -eq $Property) {
                    if ($reference.appliesTo) {
                        foreach ($appliesTo in $reference.appliesTo) {
                            if ($appliesTo.object -eq $ObjectType) {
                                return [PSCustomObject]@{
                                    id              = $reference.id
                                    category        = $reference.category
                                    attribute       = $reference.attribute
                                    riskLevel       = $reference.riskLevel
                                    attackTechnique = $appliesTo.impact
                                    objectType      = $appliesTo.object
                                    knownTools      = $reference.knownTools
                                    referenceURL    = $reference.referenceURL
                                }
                            }
                        }
                    }
                    else {
                        # If the reference matches the property but has no appliesTo field, return it with the provided ObjectType for context
                        return [PSCustomObject]@{
                            id              = $reference.id
                            category        = $reference.category
                            attribute       = $reference.attribute
                            riskLevel       = $reference.riskLevel
                            attackTechnique = $reference.attackTechnique
                            objectType      = 'no specific object type (general reference)'
                            knownTools      = $reference.knownTools
                            referenceURL    = $reference.referenceURL
                        }
                    }
                }
            }
        }

        return $null
    }

    # Grant permissions to the AD object
    function Grant-AdPermission {
        param (
            [Parameter(Mandatory)]
            [string]$Identity,
                
            [Parameter(Mandatory)]
            [string]$ObjectPathDN,
                    
            [Parameter(Mandatory)]
            [guid]$InheritedObjectType,
                    
            [Parameter(Mandatory)]
            [guid]$ObjectType,
                    
            [Parameter(Mandatory)]
            [System.DirectoryServices.ActiveDirectoryRights]$Rights,

            [Parameter(Mandatory = $false)]
            [string]$AppliesTo = $null
        )
                
        $adObject = [ADSI]"LDAP://$ObjectPathDN"
        $ace = $null
                
        # Check if the object should applies to the current object class
        if ($AppliesTo) {
            $adSchemaObject = $adObject.SchemaClassName
            [string[]]$appliesToArray = $AppliesTo.split(',')

            if ($appliesToArray -notcontains $adSchemaObject) {
                Write-Warning -Message "[Grant-AdPermission] The Template is not supposed to apply on this ObjectClass."
            }
        }
                
        # BUILD Access Control Entry 
        if ($InheritedObjectType -eq [guid]::Empty) {

            # SCOPE
            # For scope entries, the InheritedObjectType is set to 0 and the ObjectType specifies the target class 
            # (e.g., 'user', 'group') for Create Child/Delete Child rights. The ACE is created with ObjectType = ObjectType 
            # and Inheritance = All.
            $ace = New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList (
                [System.Security.Principal.NTAccount]$Identity, 
                [System.DirectoryServices.ActiveDirectoryRights]$Rights,
                [System.Security.AccessControl.AccessControlType]::Allow,
                    
                [GUID]$ObjectType,
                [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
            )
        }
        else {
                
            # CLASS
            # For class-level permissions, the ACE is created with ObjectType = InheritedObjectType and Inheritance = Descendents. 
            # If ObjectType is 0, it applies to the entire class; otherwise, it applies to the specific permissionsOrPropertiesItem.
            If ($ObjectType -eq [guid]::Empty) {
                # @
                $ace = New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList (
                    [System.Security.Principal.NTAccount]$Identity, 
                    [System.DirectoryServices.ActiveDirectoryRights]$Rights,
                    [System.Security.AccessControl.AccessControlType]::Allow,
                        
                    [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,
                    [GUID]$InheritedObjectType
                )
            }
            else {
                    
                # PROPERTY
                # For property-level permissions, the ACE is created with ObjectType = ObjectType and Inheritance = Descendents, 
                # and the InheritedObjectType is specified in the ACE to indicate which class's permissionsOrPropertiesItem is being secured.
                $ace = New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList (
                    [System.Security.Principal.NTAccount]$Identity, 
                    [System.DirectoryServices.ActiveDirectoryRights]$Rights,
                    [System.Security.AccessControl.AccessControlType]::Allow,
                        
                    [GUID]$ObjectType,
                    [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,
                    [GUID]$InheritedObjectType
                )
            }
        }

        $adObject.ObjectSecurity.AddAccessRule($ace)    
        $adObject.CommitChanges()
                
        $verboseMessage = "[*] Applied permission:`n`tADIdentity = $Identity,`n`tOU = $ObjectPathDN,`n`tRight = $Rights,`n`tObject Class GUID = $InheritedObjectType,`n`tProperty GUID = $ObjectType"
        Write-Verbose -Message $verboseMessage
    }

    # Resolves a display name for the object type of a template.
    # Priority: explicit ObjectClass field > derived from ObjectTypes > fallback "General"
    function Resolve-ObjectTypeName {
        param (
            [PSCustomObject]$Template
        )

        # If the template has an explicit ObjectClass field, use it directly for display purposes. 
        if ($Template.ObjectClass) {
            return $Template.ObjectClass 
        }

        # If no explicit ObjectClass is provided, attempt to derive a display name from the ObjectTypes field. 
        $derived = ($Template.ObjectTypes -split '[,\s]+' | Where-Object { $_ -ne 'SCOPE' } | Select-Object -First 1 )
        if ($derived) {
            # Convert the derived name to title case for display purposes
            return (Get-Culture).TextInfo.ToTitleCase($derived.ToLower()) 
        }

        # If neither ObjectClass nor ObjectTypes provide a usable name, return a generic "General" type for display purposes.
        return 'General'
    }

    # Show all templates
    function Show-Templates {
        param (
            [Parameter(HelpMessage = "Include permissionTemplate details and source file information in the output")]
            [switch]$IncludeDetails
        )

        # Define preferred category display order; unlisted categories appear at the end
        $categoryOrder = @('Account Lifecycle', 'Password', 'General', 'Account', 'Security')

        # Outer grouping: by object type, preserving file order via SourceFile sort
        $byObjectType = $delegationTemplates |
        Sort-Object { $_.SourceFile } |
        Group-Object -Property { Resolve-ObjectTypeName -Template $_ }

        foreach ($typeGroup in $byObjectType) {
            # Format Object type header
            $line = '═' * 26
            Write-Host -Object "`n$line" -ForegroundColor Cyan
            Write-Host -Object " $($typeGroup.Name)" -ForegroundColor Cyan
            Write-Host -Object "$line" -ForegroundColor Cyan

            # Inner grouping: by Category
            $grouped = $typeGroup.Group |
            Group-Object -Property { if ($_.Category) { $_.Category } else { 'Uncategorized' } }

            $sorted = @(
                foreach ($cat in $categoryOrder) {
                    $grouped | Where-Object { $_.Name -eq $cat }
                }
                $grouped | Where-Object { $_.Name -notin $categoryOrder }
            )

            foreach ($group in $sorted) {
                # Print category header with underline
                Write-Host -Object "`n  $($group.Name)" -ForegroundColor Yellow
                Write-Host -Object "  $('-' * $group.Name.Length)" -ForegroundColor Yellow

                foreach ($template in $group.Group) {
                        
                    # Output template summary line
                    Write-Host -Object ("    Template {0}: {1} [{2}]" -f $template.ID, $template.Description, $template.SourceFile)

                    # If IncludeDetails is specified, show AppliesTo and Template rules with indentation
                    if ($IncludeDetails) {
                        if ($template.AppliesTo) {
                            Write-Host "      AppliesTo: $($template.AppliesTo)"
                        }
                        if ($template.Template) {
                            Write-Host "      Rules:"
                            foreach ($permissionTemplate in $template.Template) {
                                Write-Host "        Class: $($permissionTemplate.Class) | Property: $($permissionTemplate.Property) | Right: $($permissionTemplate.Right)"
                            }
                        }
                        Write-Host "      SourceFile: $($template.SourceFile)`n"
                    }
                }
            }
        }
    }

    # Writes a Logging for Changes, to revert Changes easyly
    function Write-PermissionChangesToLog {
        param (
            [Parameter(Mandatory)]
            [string]$LogFilePath,

            [Parameter(Mandatory)]
            [string]$TemplateID,

            [Parameter(Mandatory)]
            [string]$ObjectPathDN,

            [Parameter(Mandatory)]
            [string]$Identity,

            [Parameter(Mandatory)]
            [System.DirectoryServices.ActiveDirectoryRights]$Rights,

            [string]$InheritedObjectType = $null,
            [string]$ObjectType = $null,
            [string]$AppliesTo = $null
        )

        $currentDate = (Get-Date).ToShortDateString()
        $currentTime = (Get-Date).ToShortTimeString()
                
        # Datum, Uhrzeit, TemplateID, OU, Identity, Permisson, ObjectClass, Property,
        $fileData = "$currentDate;$currentTime;$TemplateID;$ObjectPathDN;$Identity;$Rights;$InheritedObjectType;$ObjectType;"

        try {
            Out-File -FilePath $LogFilePath -InputObject $fileData -Encoding utf8 -Append -NoClobber | Out-Null
        }
        catch {
            Write-Error -Message "[Write-PermissionChangesToLog] Could not write Log for permission changes! $_"
        }
    }


    #
    # Load Templates
    #

    # Import Security Templates
    $securityTemplateList = Import-SecurityTemplate -Path $AutoSecurityTemplatePath

    # Import Delegation Templates 
    If ($AutoTemplatesLoader -or $TemplatePath) {

        # Set the template path for auto-loading 
        if ($TemplatePath) { $AutoTemplatesPath = $TemplatePath }

        # Import Templates from JSON file(s) 
        $importedTemplates = @()
        if (Test-Path -LiteralPath $AutoTemplatesPath) {
            Write-Verbose "[Invoke-ADDelegationTemplate] Loading templates from '$AutoTemplatesPath'"
            try {
                $importedTemplates = Import-ExternalTemplates -Path $AutoTemplatesPath
            }
            catch {
                Write-Warning "[Invoke-ADDelegationTemplate] Failed to auto-import templates: $($_.Exception.Message)"
            }
        }
        else {
            Write-Warning "[Invoke-ADDelegationTemplate] No TemplatePath provided and auto-template path '$AutoTemplatesPath' not found."
            Write-Warning "[Invoke-ADDelegationTemplate] Please provide a valid TemplatePath to load delegation templates or disable auto-loading by setting `$AutoTemplatesLoader = $false`."
        }

        # Remove existing entries with the same ID before adding the new template, ensuring that the last template with a given ID takes precedence without creating duplicates. This also provides clear logging about how many existing templates were removed for each imported template.
        $delegationTemplates = foreach ($permissionTemplate in $importedTemplates) {
            $delegationTemplates = $delegationTemplates | Where-Object { $_.ID -ne $permissionTemplate.ID }
            $permissionTemplate
                
            Write-Verbose "[Invoke-ADDelegationTemplate] template ID $($permissionTemplate.ID) from '$($permissionTemplate.SourceFile)' merged (last-writer-wins)."
        }
    }
}
        
process {

    # Show Templates
    if ($PSCmdlet.ParameterSetName -like 'Viewer') {
        Show-Templates -IncludeDetails:$IncludeDetails
        continue 
    }

    # Parameter validation
    if ($LogChanges) {
        if (-not $LogPath) {
            Write-Error -Message 'No valid LogPath-Param found!'
            Write-Error -Message 'Please provide a valid path for logging with -LogPath when using -LogChanges.'
            continue
        }
    }

    # Do the Job...
    try {
                
        # Apply multiple Templates
        Foreach ($templateID in $TemplateIDs) {
                    
            # Find choosen Template
            $selectedTemplate = $delegationTemplates | Where-Object { $_.ID -eq $templateID } 
            Write-Verbose -Message "[Invoke-ADDelegationTemplate] Selected template for ID $templateID - '$($selectedTemplate.Description)' from source '$($selectedTemplate.SourceFile)'"

            if ($null -eq $selectedTemplate) {
                # No Template found!
                Write-Warning -Message "[Invoke-ADDelegationTemplate] No template with ID $($templateID.ToString()) found!"
                Write-warning -Message "[Invoke-ADDelegationTemplate] Use -ShowTemplates to see available templates and their IDs."
                continue
            }                


            #
            # Check Security Template
            #

            if (-not $DisableSecurityWarning) {
                Write-Verbose -Message "[Invoke-ADDelegationTemplate] Checking security template for properties used in template ID $templateID..."

                # Collect all unique properties and permissions from the selected templates
                $permissionsOrPropertiesToCheck = @{}
                foreach ($permissionTemplate in $selectedTemplate.Template) {

                    # Add Right to check list (for @ permissions)
                    if ($permissionTemplate.Property -eq '@' -and (-not $permissionsOrPropertiesToCheck[$permissionTemplate.Right])) {
                        $permissionsOrPropertiesToCheck[$permissionTemplate.Right] = $permissionTemplate.ObjectType
                        continue
                    }

                    # Add Property to check list 
                    if ($permissionTemplate.ObjectType -ne 'SCOPE' -and (-not $permissionsOrPropertiesToCheck[$permissionTemplate.Property])) {
                        $permissionsOrPropertiesToCheck[$permissionTemplate.Property] = $permissionTemplate.ObjectType
                    }
                }
                    
                # Check if the Attribute is in the Security Template, if the template contains properties
                $foundInsecureProperty = $false
                if ($permissionsOrPropertiesToCheck.Count -gt 0 -and $securityTemplateList) {
                        
                    foreach ($permissionsOrPropertiesItem in $permissionsOrPropertiesToCheck.Keys) {

                        # Find security template permissionTemplate for the current permissionsOrPropertiesItem (unique after v2.0.0 consolidation)
                        $securityTemplateReferenceItem = Find-SecurityTemplateReference -Property $permissionsOrPropertiesItem -ObjectType $permissionsOrPropertiesToCheck[$permissionsOrPropertiesItem]
                        
                        if ($securityTemplateReferenceItem) {
                                
                            # Get the numeric severity score for the template's risk level
                            $propertyRiskLevel = $warnSeverityMap[$securityTemplateReferenceItem.riskLevel]
                                
                            If ($propertyRiskLevel -ge $warnSeverityScore) {
                                    
                                # Security Output Reference
                                Write-Host -Object "------------------------------------------------------------------------" -ForegroundColor Yellow
                                Write-Host -Object "WARNING: Property '$permissionsOrPropertiesItem' has a security warning." -ForegroundColor Yellow
                                Write-Host -Object "  - Template ID: $($selectedTemplate.id)" -ForegroundColor Yellow
                                Write-Host -Object "  - Category: $($securityTemplateReferenceItem.category)" -ForegroundColor Yellow
                                Write-Host -Object "  - Risk Level: $($securityTemplateReferenceItem.riskLevel)" -ForegroundColor Yellow
                                Write-Host -Object "  - Attack Technique: $($securityTemplateReferenceItem.attackTechnique)" -ForegroundColor Yellow
                                if ($securityTemplateReferenceItem.knownTools) {
                                    Write-Host -Object "  - Known Tools: $($securityTemplateReferenceItem.knownTools -join ', ')" -ForegroundColor Yellow
                                }
                                if ($securityTemplateReferenceItem.referenceURL) {
                                    Write-Host -Object "  - Reference: $($securityTemplateReferenceItem.referenceURL)" -ForegroundColor Yellow
                                }
                            }
                            else {
                                Write-Verbose -Message "[Invoke-ADDelegationTemplate] Property '$permissionsOrPropertiesItem' has a security warning with severity '$($securityTemplateReferenceItem.riskLevel)', which does not meet the warning threshold of '$WarnSeverity'."
                            }

                            $foundInsecureProperty = $true
                        }
                        else {
                            Write-Verbose -Message "[Invoke-ADDelegationTemplate] Property '$permissionsOrPropertiesItem' is not listed in the security template."
                        }
                    }
                }

                if ($foundInsecureProperty -eq $true) {
                    # Ask for confirmation to proceed if any insecure properties were found that meet the severity threshold

                    $confirmation = Read-Host -Prompt "One or more properties in this template have security warnings that meet the specified severity threshold. Do you want to continue applying this template? (Y/N)"
                    if ($confirmation -notin @('Y', 'y')) {
                        Write-Host -Object "Aborting applying template ID $templateID due to security warnings." -ForegroundColor Red
                        continue
                    }
                }
            }
            else {
                Write-Verbose -Message "[Invoke-ADDelegationTemplate] No properties to check against the security template or security template not available."
            }
                        

            #
            # Apply delegation Template
            #

            # Apply multiple template Permission Rules
            Foreach ($permissionTemplate in $selectedTemplate.Template) {
                Write-Verbose -Message "[Invoke-ADDelegationTemplate] Applying permission rule for ObjectType '$($permissionTemplate.ObjectType)' and Property '$($permissionTemplate.Property)'"

                #
                # Mapping ObjectType 
                #

                if ($permissionTemplate.ObjectType -like 'scope') {
                    # Permission is set to a container
                    $inheritedObjectType = [guid]::Empty
                }
                elseif ($permissionTemplate.ObjectType -match '^[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}$') {
                    # ObjectType is already a GUID, use it directly
                    $inheritedObjectType = $permissionTemplate.ObjectType
                }
                else {
                    # ObjectType is a class name, look up the corresponding GUID in the schema
                    $inheritedObjectType = Get-ObjectTypeGUID -Name $permissionTemplate.ObjectType -GuidStore 'Schema'
                }

                #
                # Mapping Property to GUID
                #

                $ObjectType = ''
                if ($permissionTemplate.Property -eq '@') {
                    # Use empty GUID to indicate the entire class for property-level permissions
                    $ObjectType = [guid]::Empty
                }
                elseif ($permissionTemplate.Property -match '^[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}$') {
                    # Property is already a GUID, use it directly
                    $ObjectType = $permissionTemplate.Property
                }
                else {
                    if ("ExtendedRight", "Self" -contains $permissionTemplate.Right) {
                        # For Extended Rights, we need to look up the rightsGuid instead of ObjectGUID
                        $ObjectType = Get-ObjectTypeGUID -Name $permissionTemplate.Property -GuidStore 'ExtendedRights' | Select-Object -First 1
                    }
                    else {
                        # For regular properties, we look up the ObjectGUID in the schema
                        $ObjectType = Get-ObjectTypeGUID -Name $permissionTemplate.Property -GuidStore 'Schema'

                        # Backup plan: If the permissionsOrPropertiesItem name cannot be resolved and is a GUID, it might be an extended right, so we try looking it up in ExtendedRights as well.
                        if ($null -eq $ObjectType) {
                            $ObjectType = Get-ObjectTypeGUID -Name $permissionTemplate.Property -GuidStore 'ExtendedRights' | Select-Object -First 1
                        }
                    }
                }
                    
                # Setup parameters for Grant-AdPermission
                $params = @{
                    'Identity'            = $Identity
                    'ObjectPathDN'        = $Path
                    'InheritedObjectType' = $inheritedObjectType
                    'ObjectType'          = $ObjectType
                    'Right'               = $permissionTemplate.Right
                    'AppliesTo'           = $selectedTemplate.AppliesTo
                }    
                    
                # Grant permissions based on the current template rule
                Grant-AdPermission @params
                    
                # Log changes
                if ($LogChanges) {
                    Write-PermissionChangesToLog -TemplateID $templateID -LogFilePath $LogPath @params
                }
            }
                
            Write-Verbose -Message "[Invoke-ADDelegationTemplate] Template $templateID applied successfully."
        }
    }
    catch {
        # Error
        Write-Host -Object "[Invoke-ADDelegationTemplate] Could not apply permissions! $_" -ForegroundColor Red
    }
}
        
end {
    Write-Verbose -Message '[Invoke-ADDelegationTemplate] END'
}