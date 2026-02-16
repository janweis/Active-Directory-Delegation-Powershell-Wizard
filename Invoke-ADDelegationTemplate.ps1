#requires -Version 3.0
<#
    .SYNOPSIS
    Apply delegation templates (JSON-based) to Active Directory objects or list available templates.

    .DESCRIPTION
    This script allows you to apply predefined delegation templates to Active Directory objects, granting specific permissions based
    on the rules defined in the templates. Templates are defined in external JSON files, which can be loaded from a specified path. 
    The script also supports listing available templates and logging applied changes for auditing purposes.

    .AUTHOR 
    Jan Weis
    
    .VERSION
    v1.3-dev

    .NOTES
    v1.3-dev Changelog:
    + [NEW] Import external templates from JSON (Import-ExternalTemplates)
    + [NEW] Validate-DelegationTemplateStructure (schema validation with warnings)
    + [IMPROVE] Show-Templates now displays Origin/SourceFile
    + [IMPROVE] Safer merge logic for external templates (last-writer-wins)
    + [DOC] Added templates/README and generated example JSON files
    + [FIX] Improved error handling and logging for template loading and validation
    + [FIX] Corrected handling of Rights parsing and validation (expecting full enum names)
    + [FIX] Added support for both single object and array formats in JSON template files

    .PARAMETER AdIdentity
    Identity reference (name, SID or AD object) that will receive permissions.

    .PARAMETER AdObjectPathDN
    Target Organizational Unit or AD object in distinguishedName format.

    .PARAMETER TemplateIDs
    One or more template IDs to apply (integer values from available templates).

    .PARAMETER TemplatePath
    Path to a JSON file or a directory containing external delegation templates. **This parameter is required** — the script contains no built-in templates; always provide `-TemplatePath` to load templates.
    Template rule `Right` must use full ActiveDirectoryRights enum names (for example: `ReadProperty`, `WriteProperty`, `ExtendedRight`). Abbreviations (for example `RP`, `WP`, `CONTROLRIGHT`) are no longer accepted.
    If a directory is provided, all *.json files are loaded alphabetically and merged (external entries override templates by ID).

    .PARAMETER LogChanges
    Switch to enable logging of applied permission changes.

    .PARAMETER LogPath
    Path to the log file (used when -LogChanges is specified).

    .PARAMETER ShowTemplates
    Show a list of templates that can be applied.

    .PARAMETER IncludeDetails
    When used with -ShowTemplates, display rule details and the source file.

    .EXAMPLE
    # List available templates 
    Invoke-ADDelegationTemplate -ShowTemplates -TemplatePath .\templates

    # List available templates with details
    Invoke-ADDelegationTemplate -TemplatePath .\templates -ShowTemplates -IncludeDetails

    # Apply template 101 to an OU for a group identity and log changes
    Invoke-ADDelegationTemplate -AdIdentity 'CN=UserManagers,OU=Groups,DC=contoso,DC=local' -AdObjectPathDN 'OU=MyOU,DC=contoso,DC=local' -TemplateIDs 101 -LogChanges -LogPath .\delegation.log
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory, ParameterSetName = 'DoTheMagic')]
    [string]$AdIdentity,

    [Parameter(Mandatory, ParameterSetName = 'DoTheMagic')]
    [string]$AdObjectPathDN,

    [Parameter(Mandatory, ParameterSetName = 'DoTheMagic')]
    [int[]]$TemplateIDs,

    [Parameter()]
    [string]$TemplatePath,
        
    [Parameter(ParameterSetName = 'DoTheMagic')]
    [switch]$LogChanges,

    [Parameter(ParameterSetName = 'DoTheMagic')]
    [string]$LogPath,

    [Parameter(ParameterSetName = 'Viewer')]
    [switch]$ShowTemplates,
		
    [Parameter(ParameterSetName = 'Viewer')]
    [switch]$IncludeDetails
)
    
begin {
    Write-Verbose -Message '[Invoke-ADDelegationTemplate] START'

    #
    # Constants and Mappings
    #

    # GUIDs for Classes
    $classGuidsMap = @{
        'scope'              = '0' # Scope Object (Used for Create Child and Delete Child Rights)
        'user'               = 'bf967aba-0de6-11d0-a285-00aa003049e2' # User Object
        'group'              = 'bf967a9c-0de6-11d0-a285-00aa003049e2' # Group Object
        'computer'           = 'bf967a86-0de6-11d0-a285-00aa003049e2' # Computer Object
        'organizationalUnit' = 'bf967aa5-0de6-11d0-a285-00aa003049e2' # Organizational Unit Object
        'inetOrgPerson'      = '4828cc14-1437-45bc-9b07-ad6f015e5f28' # inetOrgPerson Object
        'msWMI-Som'          = '17b8b2f3-35e1-4c7c-b9b0-dba7750c9e4d' # WMI-Filter
        'gPLink'             = 'f30e3bbe-9ff0-11d1-b603-0000f80367c1' # Group Policy Link
        'gPOptions'          = 'f30e3bbf-9ff0-11d1-b603-0000f80367c1' # Group Policy Options
    }
        
    # GUIDS for Class Properties & ControlRights
    $propertyGuidsMap = @{
        '@'                                           = '0' # Special value for "@" meaning "all properties" (used for class-level permissions)
        'Reset Password'                              = '00299570-246d-11d0-a768-00aa006e0529'
        'Change Password'                             = 'ab721a53-1e2f-11d0-9819-00aa0040529b'
        'Generate Resultant Set of Policy (Logging)'  = 'b7b1b3de-ab09-4242-9e30-9980e5d322f7'
        'Generate Resultant Set of Policy (Planning)' = 'b7b1b3dd-ab09-4242-9e30-9980e5d322f7'
        'cn'                                          = 'bf96793f-0de6-11d0-a285-00aa003049e2'
        'name'                                        = 'bf967a0e-0de6-11d0-a285-00aa003049e2'
        'displayName'                                 = 'bf967953-0de6-11d0-a285-00aa003049e2'
        'sAMAccountName'                              = '3e0abfd0-126a-11d0-a060-00aa006c33ed'
        'userAccountControl'                          = 'bf967a68-0de6-11d0-a285-00aa003049e2'
        'description'                                 = 'bf967950-0de6-11d0-a285-00aa003049e2'
        'info'                                        = 'bf96793e-0de6-11d0-a285-00aa003049e2'
        'managedBy'                                   = '0296c120-40da-11d1-a9c0-0000f80367c1'
        'telephoneNumber'                             = 'bf967a49-0de6-11d0-a285-00aa003049e2'
        'wWWHomePage'                                 = 'bf967a7a-0de6-11d0-a285-00aa003049e2'
        'userPrincipalName'                           = '28630ebb-41d5-11d1-a9c1-0000f80367c1'
        'accountExpires'                              = 'bf967915-0de6-11d0-a285-00aa003049e2'
        'lockoutTime'                                 = '28630ebf-41d5-11d1-a9c1-0000f80367c1'
        'pwdLastSet'                                  = 'bf967a0a-0de6-11d0-a285-00aa003049e2'
        'physicalDeliveryOfficeName'                  = 'bf9679f7-0de6-11d0-a285-00aa003049e2'
        'logonHours'                                  = 'bf9679ab-0de6-11d0-a285-00aa003049e2'
        'userWorkstations'                            = 'bf9679d7-0de6-11d0-a285-00aa003049e2'
        'profilePath'                                 = 'bf967a05-0de6-11d0-a285-00aa003049e2'
        'scriptPath'                                  = 'bf9679a8-0de6-11d0-a285-00aa003049e2'
        'ou'                                          = 'bf9679f0-0de6-11d0-a285-00aa003049e2'
        'member'                                      = 'bf9679c0-0de6-11d0-a285-00aa003049e2'
        'groupClass'                                  = '9a9a021e-4a5b-11d1-a9c3-0000f80367c1'
        'userPassword'                                = 'bf967a6e-0de6-11d0-a285-00aa003049e2'
        'adminDisplayName'                            = 'bf96791a-0de6-11d0-a285-00aa003049e2'
        'distinguishedName'                           = 'bf9679e4-0de6-11d0-a285-00aa003049e2'
    }
        
        
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

    function Test-ExternalTemplateStructure {
        <#
                .SYNOPSIS
                Validate shape and values of an external delegation template object.
                Returns $true when valid, otherwise $false and emits warnings.
            #>
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
            $Template,

            [hashtable]
            $ClassMap = $(if (Get-Variable -Name classGuidsMap -Scope 1 -ErrorAction SilentlyContinue) { (Get-Variable -Name classGuidsMap -Scope 1).Value } else { $null }),

            [hashtable]
            $PropertyMap = $(if (Get-Variable -Name propertyGuidsMap -Scope 1 -ErrorAction SilentlyContinue) { (Get-Variable -Name propertyGuidsMap -Scope 1).Value } else { $null })
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

        foreach ($rule in $rules) {
            if (-not $rule.Class) {
                Write-Warning "Template ID $($id): a rule is missing 'Class'."
                $isValid = $false
                continue
            }

            if (-not $ClassMap -or -not $ClassMap.ContainsKey($rule.Class)) {
                Write-Warning "Template ID $($id): unknown Class '$($rule.Class)'."
                $isValid = $false
                continue
            }

            if (-not $rule.Property) {
                Write-Warning "Template ID $($id): a rule is missing 'Property'."
                $isValid = $false
                continue
            }

            $propValid = $false
            if ($rule.Property -eq '@') { $propValid = $true }
            elseif ($PropertyMap -and $PropertyMap.ContainsKey($rule.Property)) { $propValid = $true }
            elseif ($ClassMap.ContainsKey($rule.Property)) { $propValid = $true }

            if (-not $propValid) {
                Write-Warning "Template ID $($id): unknown Property '$($rule.Property)'."
                $isValid = $false
                continue
            }

            if (-not $rule.Right) {
                Write-Warning "Template ID $($id): a rule is missing 'Right'."
                $isValid = $false
                continue
            }

            # Validate Right(s) — expect full System.DirectoryServices.ActiveDirectoryRights names
            # Support comma or '|' separated lists and arrays; parsing is case-insensitive.
            $rightsToCheck = @()
            if ($rule.Right -is [System.Collections.IEnumerable] -and -not ($rule.Right -is [string])) {
                $rightsToCheck = $rule.Right
            }
            else {
                $rightsToCheck = ($rule.Right -split '[,|]') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
            }

            $invalidRight = $null
            foreach ($rt in $rightsToCheck) {
                $parsed = $null
                if (-not [System.Enum]::TryParse([System.DirectoryServices.ActiveDirectoryRights], $rt, $true, [ref]$parsed)) {
                    $invalidRight = $rt
                    break
                }
            }

            if ($invalidRight) {
                $allowed = ([Enum]::GetNames([System.DirectoryServices.ActiveDirectoryRights]) -join ', ')
                Write-Warning "Template ID $($id): unknown Right '$($invalidRight)'. Allowed values: $allowed"
                $isValid = $false
                continue
            }
        }

        return $isValid
    }

    # Convert template-specified rights (string or array) to a combined ActiveDirectoryRights enum value
    function Convert-TemplateRightsToADRights {
        param(
            [Parameter(Mandatory = $true)]
            $RightSpec
        )

        # Return a bitwise-combined System.DirectoryServices.ActiveDirectoryRights value
        [System.DirectoryServices.ActiveDirectoryRights]$result = 0

        $tokens = @()
        if ($RightSpec -is [System.Collections.IEnumerable] -and -not ($RightSpec -is [string])) {
            $tokens = $RightSpec
        }
        else {
            $tokens = ($RightSpec -split '[,|]') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
        }

        foreach ($t in $tokens) {
            $parsed = $null
            if (-not [System.Enum]::TryParse([System.DirectoryServices.ActiveDirectoryRights], $t, $true, [ref]$parsed)) {
                throw "Invalid ActiveDirectoryRights value '$t'"
            }
            $result = $result -bor $parsed
        }

        return $result
    }

    # Grant permissions to the AD object
    function Grant-AdPermission {
        param (
            [Parameter(Mandatory)]
            [string]$Identity,
            
            [Parameter(Mandatory)]
            [string]$ObjectPathDN,
                
            [Parameter(Mandatory)]
            [string]$ClassGUID,
                
            [Parameter(Mandatory)]
            [string]$PropertyGUID,
                
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
        if ($ClassGUID -eq 0) {
            # SCOPE
            $ace = New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList (
                [System.Security.Principal.NTAccount]$Identity, 
                [System.DirectoryServices.ActiveDirectoryRights]$Rights,
                [System.Security.AccessControl.AccessControlType]::Allow,
                [GUID]$PropertyGUID,
                [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
            )
        }
        else {
            # CLASS
            If ($PropertyGUID -eq 0) {
                # @
                $ace = New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList (
                    [System.Security.Principal.NTAccount]$Identity, 
                    [System.DirectoryServices.ActiveDirectoryRights]$Rights,
                    [System.Security.AccessControl.AccessControlType]::Allow,
                    [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,
                    [GUID]$ClassGUID
                )
            }
            else {
                # PROPERTY
                $ace = New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList (
                    [System.Security.Principal.NTAccount]$Identity, 
                    [System.DirectoryServices.ActiveDirectoryRights]$Rights,
                    [System.Security.AccessControl.AccessControlType]::Allow,
                    [GUID]$PropertyGUID,
                    [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,
                    [GUID]$ClassGUID
                )
            }
        }

        $adObject.ObjectSecurity.AddAccessRule($ace)    
        $adObject.CommitChanges()
            
        $verboseMessage = "[*] Applied permission:`n`tADIdentity = $Identity,`n`tOU = $ObjectPathDN,`n`tRight = $Rights,`n`tObject Class GUID = $ClassGUID,`n`tProperty GUID = $PropertyGUID"
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
                    foreach ($rule in $template.Template) {
                        Write-Host "`tClass: $($rule.Class) | Property: $($rule.Property) | Right: $($rule.Right)"
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

            [string]$ClassGUID = $null,
            [string]$PropertyGUID = $null,
            [string]$AppliesTo = $null
        )

        $currentDate = (Get-Date).ToShortDateString()
        $currentTime = (Get-Date).ToShortTimeString()
            
        # Datum, Uhrzeit, TemplateID, OU, Identity, Permisson, ObjectClass, Property,
        $fileData = "$currentDate;$currentTime;$TemplateID;$ObjectPathDN;$Identity;$Rights;$ClassGUID;$PropertyGUID;"

        try {
            Out-File -FilePath $LogFilePath -InputObject $fileData -Encoding utf8 -Append -NoClobber | Out-Null
        }
        catch {
            Write-Error -Message "[Err] Could not write Log for permission changes! $_"
        }
    }

    # Load Delegation Templates
    $importedTemplates = @()
    if ($AutoTemplatesLoader -and -not $TemplatePath) {

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

        Write-Verbose "[Invoke-ADDelegationTemplate] Loading external templates from '$TemplatePath'"
        try {
            $importedTemplates = Import-ExternalTemplates -Path $TemplatePath
        }
        catch {
            Write-Warning "[Invoke-ADDelegationTemplate] Failed to import external templates: $($_.Exception.Message)"
        }
    }

    foreach ($templateItem in $importedTemplates) {
        if (-not (Test-ExternalTemplateStructure -Template $templateItem -ClassMap $classGuidsMap -PropertyMap $propertyGuidsMap)) {
            Write-Warning "[Invoke-ADDelegationTemplate] template ID $($templateItem.ID) from '$($templateItem.SourceFile)' failed validation and was skipped."
            continue
        }

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
                
            if ($null -eq $selectedTemplate) {
                # No Template found!
                Write-Warning -Message "No template with ID $($templateID.ToString()) found!"
                Write-warning -Message "Use -ShowTemplates to see available templates and their IDs."
                break
            }                
                
            # Apply multiple template Permission Rules
            Foreach ($rule in $selectedTemplate.Template) {
                
                # Mapping Name to GUID
                $propertyGUID = ''
                if ($rule.Class -like 'scope') {
                    $propertyGUID = $classGuidsMap[$rule.Property]
                }
                else {
                    $propertyGUID = $propertyGuidsMap[$rule.Property]
                }
                
                $params = @{
                    'Identity'     = $AdIdentity
                    'ObjectPathDN' = $AdObjectPathDN
                    'ClassGUID'    = $classGuidsMap[$rule.Class]
                    'PropertyGUID' = $propertyGUID
                    'Right'        = Convert-TemplateRightsToADRights $rule.Right
                    'AppliesTo'    = $selectedTemplate.AppliesTo
                }
                
                # Set Permissions to Object
                Grant-AdPermission @params
                
                # Log changes
                if ($LogChanges) {
                    Write-PermissionChangesToLog -TemplateID $templateID -LogFilePath $LogPath @params
                }

                Write-Verbose -Message "[info] Template $templateID applied successfully."
            }
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
