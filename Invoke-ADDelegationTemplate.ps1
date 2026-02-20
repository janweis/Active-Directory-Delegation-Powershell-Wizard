#requires -Version 3.0
<#
    .SYNOPSIS
    Apply delegation templates (JSON-based) to Active Directory objects or list available templates.

    .DESCRIPTION
    This script allows you to apply predefined delegation templates to Active Directory objects, granting specific permissions based
    on the rules defined in the templates. Templates are defined in external JSON files, which can be loaded from a specified path or 
    are automatically loaded from a 'templates' subdirectory. The script dynamically resolves AD schema GUIDs, supports full 
    ActiveDirectoryRights enum names, and logs applied changes for auditing and rollback purposes.

    .AUTHOR 
    Jan Weis
    
    .VERSION
    v1.3-dev

    .NOTES
    v1.3-dev Changelog:
    + [NEW] Completely externalized templates to JSON files (no hardcoded templates in script).
    + [NEW] Auto-loader for templates from a 'templates' subdirectory.
    + [NEW] Dynamic AD Schema resolution (Get-ObjectTypeGUID) replaces hardcoded GUID mapping tables.
    + [NEW] Support for full ActiveDirectoryRights enum names (e.g., ReadProperty, ExtendedRight) and multiple rights per rule.
    + [IMPROVE] Show-Templates now displays Origin/SourceFile and uses color coding.
    + [IMPROVE] Safer merge logic for external templates (last-writer-wins on duplicate IDs).
    + [IMPROVE] Enhanced logging format (semicolon-separated) for better compatibility with Revert-ADDelegationTemplate.
    + [DOC] Added templates/README and generated example JSON files.
    + [FIX] Removed legacy abbreviations (RP, WP, CC, etc.) in favor of standard .NET enums.

    .PARAMETER Identity
    Identity reference (name, SID or AD object) that will receive permissions.

    .PARAMETER Path
    Target Organizational Unit or AD object in distinguishedName format.

    .PARAMETER TemplateIDs
    One or more template IDs to apply (integer values from available templates).

    .PARAMETER TemplatePath
    Path to a JSON file or a directory containing external delegation templates. **This parameter is required** — the script contains no built-in templates; always provide `-TemplatePath` to load templates.
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

    .EXAMPLE
    # List available templates 
    Invoke-ADDelegationTemplate -ShowTemplates -TemplatePath .\templates

    # List available templates with details
    Invoke-ADDelegationTemplate -TemplatePath .\templates -ShowTemplates -IncludeDetails

    # Apply template 101 to an OU for a group identity and log changes
    Invoke-ADDelegationTemplate -Identity 'CN=UserManagers,OU=Groups,DC=contoso,DC=local' -Path 'OU=MyOU,DC=contoso,DC=local' -TemplateIDs 101 -LogChanges -LogPath .\delegation.log
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
    [switch]$IncludeDetails
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
        
    # Templates
    $delegationTemplates = @()


    #
    # Functions
    #

    # Get ObjectType GUID from Schema or Extended Rights or schmema class name
    function Get-ObjectTypeGUID {
        param (
            [Parameter(Mandatory = $true, HelpMessage = "Specify the ObjectType name to look up")]
            [string]$Name,

            [Parameter(Mandatory = $true)]
            [ValidateSet("Schema", "ExtendedRights")]
            [string]$GuidStore
        )

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

        try {
            $schemaObject = Get-ADObject @searchParams

            if ($schemaObject) {
                return ($schemaObject.$propertyName -as [Guid])
            }
            else {
                Write-Warning "No schema object found for ObjectType name: $Name."
                return $null
            }
        }
        catch {
            Write-Warning "Could not retrieve ObjectType GUID for name: $Name."
            return $null
        }
    }

    # Import the external templates from JSON file(s) and return an array of template objects with SourceFile property for traceability
    function Import-ExternalTemplates {
        <#
                .SYNOPSIS
                Import external delegation templates from a JSON file or directory of JSON files.
                Returns an array of PSCustomObject templates with an added `SourceFile` property.
            #>
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true, Position = 0)]
            [string]$Path
        )

        $loaded = @()

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

            # Validate and flatten templates, adding SourceFile property. Also check for duplicate IDs 
            # within the same file to avoid conflicts.
            $seenIds = @{}
            foreach ($template in $templatesInFile) {
                if ($null -eq $template.ID) {
                    Write-Warning "Template in file '$($file.Name)' missing property 'ID' — skipping."
                    continue
                }

                try { $tid = [int]$template.ID } catch {
                    Write-Warning "Template ID '$($template.ID)' in file '$($file.Name)' is not an integer — skipping."
                    continue
                }

                if ($seenIds.ContainsKey($tid)) {
                    Write-Warning "Duplicate template ID $tid in file '$($file.Name)' — skipping duplicate."
                    continue
                }

                $seenIds[$tid] = $true

                $obj = [PSCustomObject]@{
                    ID          = $tid
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
                Write-Warning -Message "[WARN] The Template is not supposed to apply on this ObjectClass."
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
            # If ObjectType is 0, it applies to the entire class; otherwise, it applies to the specific property.
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
                # and the InheritedObjectType is specified in the ACE to indicate which class's property is being secured.
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

    # Show all templates
    function Show-Templates([switch]$IncludeDetails) {
            
        for ($i = 0; $i -lt $delegationTemplates.Count; $i++) {
            $defaultColor = [ConsoleColor]::White
            $template = $delegationTemplates[$i]

            # Highlight templates with IDs ending in "00" (e.g., 100, 200) as default templates in cyan color
            if ($template.ID -like "*00") {
                Write-Host -Object ''
                $defaultColor = [ConsoleColor]::Cyan
            }

            # Display template information with the appropriate color
            Write-Host -Object ("Template {0}: {1} [{2}]" -f $template.ID, $template.Description, $template.SourceFile) -ForegroundColor $defaultColor

            # If IncludeDetails is specified, show AppliesTo and Template rules with indentation
            if ($IncludeDetails) {
                if ($template.AppliesTo) {
                    Write-Host "   AppliesTo: $($template.AppliesTo)"
                }
                if ($template.Template) {
                    Write-Host "   Rules:"
                    foreach ($permissionTemplate in $template.Template) {
                        Write-Host "`tClass: $($permissionTemplate.Class) | Property: $($permissionTemplate.Property) | Right: $($permissionTemplate.Right)"
                    }
                }

                # show explicit source details when available
                Write-Host "   SourceFile: $($template.SourceFile)`n"
            }
        }
    }

    # Writes a Logging for Changes, to revert Changes easyly
    function Write-PermissionChangesToLog {
        [CmdletBinding()]
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
            Write-Error -Message "[Err] Could not write Log for permission changes! $_"
        }
    }

    # Load Templates
    $importedTemplates = @()
    if ($AutoTemplatesLoader -and -not $TemplatePath) {
        # Autoloader

        if (Test-Path -LiteralPath $AutoTemplatesPath) {
            Write-Verbose "[Invoke-ADDelegationTemplate] Auto-loading templates from '$AutoTemplatesPath'"
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
    }
    else {
        # Path-Loader

        Write-Verbose "[Invoke-ADDelegationTemplate] Loading external templates from '$TemplatePath'"
        try {
            $importedTemplates = Import-ExternalTemplates -Path $TemplatePath
        }
        catch {
            Write-Warning "[Invoke-ADDelegationTemplate] Failed to import external templates: $($_.Exception.Message)"
        }
    }

    foreach ($templateItem in $importedTemplates) {

        # Remove any existing entries with the same ID and append the external template (last-writer-wins)
        $existingCount = ($delegationTemplates | Where-Object { $_.ID -eq $templateItem.ID }).Count
        if ($existingCount -gt 0) {
            $delegationTemplates = $delegationTemplates | Where-Object { $_.ID -ne $templateItem.ID }
            Write-Verbose "[Invoke-ADDelegationTemplate] Removed $existingCount existing template(s) with ID $($templateItem.ID)."
        }

        $delegationTemplates += $templateItem
        Write-Verbose "[Invoke-ADDelegationTemplate] template ID $($templateItem.ID) from '$($templateItem.SourceFile)' merged (appended)."
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
                
            # Get Template
            $selectedTemplate = $delegationTemplates | Where-Object { $_.ID -eq $templateID } 
            Write-Verbose -Message "Selected template for ID $templateID - '$($selectedTemplate.Description)' from source '$($selectedTemplate.SourceFile)'"

            if ($null -eq $selectedTemplate) {
                # No Template found!
                Write-Warning -Message "No template with ID $($templateID.ToString()) found!"
                Write-warning -Message "Use -ShowTemplates to see available templates and their IDs."
                break
            }                
                
            # Apply multiple template Permission Rules
            Foreach ($permissionTemplate in $selectedTemplate.Template) {
                Write-Verbose -Message "Applying permission rule for ObjectType '$($permissionTemplate.ObjectType)' and Property '$($permissionTemplate.Property)'"

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
                    if($permissionTemplate.Right -match 'ExtendedRight') {
                        # For Extended Rights, we need to look up the rightsGuid instead of ObjectGUID
                        $ObjectType = Get-ObjectTypeGUID -Name $permissionTemplate.Property -GuidStore 'ExtendedRights'
                    }
                    else {
                        # For regular properties, we look up the ObjectGUID in the schema
                        $ObjectType = Get-ObjectTypeGUID -Name $permissionTemplate.Property -GuidStore 'Schema'
                    }
                }

                # Create parameters for Grant-AdPermission function
                $params = @{
                    'Identity'            = $Identity
                    'ObjectPathDN'        = $Path
                    'InheritedObjectType' = $inheritedObjectType
                    'ObjectType'          = $ObjectType
                    'Right'               = $permissionTemplate.Right
                    'AppliesTo'           = $selectedTemplate.AppliesTo
                }
                
                # Set Permissions to Object
                Grant-AdPermission @params
                
                # Log changes
                if ($LogChanges) {
                    Write-PermissionChangesToLog -TemplateID $templateID -LogFilePath $LogPath @params
                }
            }
            
            Write-Verbose -Message "[info] Template $templateID applied successfully."
        }
    }
    catch {
        # Error
        Write-Host -Object "[err] Could not apply permissions! $_" -ForegroundColor Red
    }
}
    
end {
    Write-Verbose -Message '[Invoke-ADDelegationTemplate] END'
}
