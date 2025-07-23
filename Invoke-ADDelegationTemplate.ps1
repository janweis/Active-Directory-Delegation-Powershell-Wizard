#requires -Version 3.0

<#
    Author: Jan Weis
    Version: 1.1
    Web: www.it-explorations.de

    v1.2
    + [FIX] Issue #2 with "AppliesTo"
    + [FIX] Issue doubled descriptions

    v1.1
    + [NEW] Complete rewrite of the script
    + [NEW] Validate 'AppliesTo'
    + [ADD] Missing Class-Object permissions now correct
    + [NEW] Remove 'GenericAll' Permissions from Templates to avoid security issues

#>
<#
        .SYNOPSIS
        This PowerShell script is used to assign permissions in Active Directory based on predefined templates. 
        It enables administrators to configure specific rights and properties for user, group, computer and OU objects in Active Directory.

        .PARAMETER AdIdentity
        Enter a IdentityReference Object (User, Group, Computer ...)

        .PARAMETER DelegationOuDN
        Enter the destination organizational unit as distinguishedName format

        .PARAMETER TemplateID
        Enter the number of the tamplate ID

        .PARAMETER ShowTemplates
        Show a list of templates that can be applied

        .EXAMPLE
        Invoke-AdDelegationTemplate -ShowTemplates

        Invoke-ADDelegationTemplate -AdIdentity UserManagerPermissionGroup -AdObjectPathDN "OU=MySpecialOU,DC=ad,DC=MyADDomain,DC=de" -TemplateID 101
#>
function Invoke-ADDelegationTemplate {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ParameterSetName = 'DoTheMagic')]
        [string]$AdIdentity,

        [Parameter(Mandatory, ParameterSetName = 'DoTheMagic')]
        [string]$AdObjectPathDN,

        [Parameter(Mandatory, ParameterSetName = 'DoTheMagic')]
        [int[]]$TemplateIDs,

        [Parameter(ParameterSetName = 'DoTheMagic')]
        [switch]$LogChanges,

        [Parameter(ParameterSetName = 'DoTheMagic')]
        [string]$LogPath,

        [Parameter(ParameterSetName = 'Viewer')]
        [switch]$ShowTemplates,
		
		[Parameter(ParameterSetName = 'Viewer')]
        [switch]$ShowTemplatesDetailed,

        [Parameter(ParameterSetName = 'Viewer')]
        [switch]$ShowUserTemplates,

        [Parameter(ParameterSetName = 'Viewer')]
        [switch]$ShowComputerTemplates,

        [Parameter(ParameterSetName = 'Viewer')]
        [switch]$ShowGroupTemplates,

        [Parameter(ParameterSetName = 'Viewer')]
        [switch]$ShowOUTemplates,

        [Parameter(ParameterSetName = 'Viewer')]
        [switch]$ShowInetOrgPersonTemplates,
        
        [Parameter(ParameterSetName = 'Viewer')]
        [switch]$ShowGPOTemplates,

        [Parameter(ParameterSetName = 'Viewer')]
        [switch]$ShowWmiTemplates
    )
    
    begin {
        Write-Verbose -Message '[Invoke-ADDelegationTemplate] START'

        # GUIDs for Classes
        $classGuidsMap = @{
            'scope' =              '0'
            'user' =               'bf967aba-0de6-11d0-a285-00aa003049e2'
            'group' =              'bf967a9c-0de6-11d0-a285-00aa003049e2'
            'computer' =           'bf967a86-0de6-11d0-a285-00aa003049e2'
            'organizationalUnit' = 'bf967aa5-0de6-11d0-a285-00aa003049e2'
            'inetOrgPerson' =      '4828cc14-1437-45bc-9b07-ad6f015e5f28'
            'msWMI-Som' =      '17b8b2f3-35e1-4c7c-b9b0-dba7750c9e4d' # WMI-Filter
            'gPLink' =         'f30e3bbe-9ff0-11d1-b603-0000f80367c1'
            'gPOptions' =      'f30e3bbf-9ff0-11d1-b603-0000f80367c1'
        }

        # RightObjects for Rights
        $rightsMap = @{
            'GA' = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
            'GE' = [System.DirectoryServices.ActiveDirectoryRights]::GenericExecute
            'GR' = [System.DirectoryServices.ActiveDirectoryRights]::GenericRead
            'GW' = [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite
            'SD' = [System.DirectoryServices.ActiveDirectoryRights]::Self
            'LC' = [System.DirectoryServices.ActiveDirectoryRights]::ListChildren
            'LO' = [System.DirectoryServices.ActiveDirectoryRights]::ListObject
            'CC' = [System.DirectoryServices.ActiveDirectoryRights]::CreateChild
            'DC' = [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild
            'DT' = [System.DirectoryServices.ActiveDirectoryRights]::DeleteTree
            'RC' = [System.DirectoryServices.ActiveDirectoryRights]::ReadControl
            'RP' = [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty
            'WD' = [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl
            'WO' = [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner
            'WP' = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
            'CONTROLRIGHT' = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
        }
        
        # GUIDS for Class Properties & ControlRights
        $propertyGuidsMap = @{
            '@' =             '0'
            'Reset Password' =  '00299570-246d-11d0-a768-00aa006e0529'
            'Change Password' = 'ab721a53-1e2f-11d0-9819-00aa0040529b'
            'Generate Resultant Set of Policy (Logging)' =  'b7b1b3de-ab09-4242-9e30-9980e5d322f7'
            'Generate Resultant Set of Policy (Planning)' = 'b7b1b3dd-ab09-4242-9e30-9980e5d322f7'
            'cn' = 'bf96793f-0de6-11d0-a285-00aa003049e2'
            'name' = 'bf967a0e-0de6-11d0-a285-00aa003049e2'
            'displayName' = 'bf967953-0de6-11d0-a285-00aa003049e2'
            'sAMAccountName' = '3e0abfd0-126a-11d0-a060-00aa006c33ed'
            'userAccountControl' = 'bf967a68-0de6-11d0-a285-00aa003049e2'
            'description' = 'bf967950-0de6-11d0-a285-00aa003049e2'
            'info' = 'bf96793e-0de6-11d0-a285-00aa003049e2'
            'managedBy' = '0296c120-40da-11d1-a9c0-0000f80367c1'
            'telephoneNumber' = 'bf967a49-0de6-11d0-a285-00aa003049e2'
            'wWWHomePage' = 'bf967a7a-0de6-11d0-a285-00aa003049e2'
            'userPrincipalName' = '28630ebb-41d5-11d1-a9c1-0000f80367c1'
            'accountExpires' = 'bf967915-0de6-11d0-a285-00aa003049e2'
            'lockoutTime' = '28630ebf-41d5-11d1-a9c1-0000f80367c1'
            'pwdLastSet' = 'bf967a0a-0de6-11d0-a285-00aa003049e2'
            'physicalDeliveryOfficeName' = 'bf9679f7-0de6-11d0-a285-00aa003049e2'
            'logonHours' = 'bf9679ab-0de6-11d0-a285-00aa003049e2'
            'userWorkstations' = 'bf9679d7-0de6-11d0-a285-00aa003049e2'
            'profilePath' = 'bf967a05-0de6-11d0-a285-00aa003049e2'
            'scriptPath' = 'bf9679a8-0de6-11d0-a285-00aa003049e2'
            'ou' = 'bf9679f0-0de6-11d0-a285-00aa003049e2'
            'member' = 'bf9679c0-0de6-11d0-a285-00aa003049e2'
            'groupClass' = '9a9a021e-4a5b-11d1-a9c3-0000f80367c1'
            'userPassword' = 'bf967a6e-0de6-11d0-a285-00aa003049e2'
            'adminDisplayName' = 'bf96791a-0de6-11d0-a285-00aa003049e2'
        }
        
        # Templates
        $delegationTemplates = @(
            
            #
            # USER
            #
            @{
                ID = 100
                Description = "`n----- USER -----`n"
            },
            @{
                ID = 101
                Description = 'Create, delete, and manage user accounts'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'user'; Property = '@'; Right = 'RP' },
                    @{ Class = 'user'; Property = '@'; Right = 'WP' },
                    @{ Class = 'user'; Property = 'Reset Password'; Right = 'CONTROLRIGHT' },
                    @{ Class = 'scope'; Property = 'user'; Right = 'CC' },
                    @{ Class = 'scope'; Property = 'user'; Right = 'DC' }
                )
            },
            @{
                ID = 102
                Description = 'Reset user passwords and force password change at next logon'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'user'; Property = 'Reset Password'; Right = 'CONTROLRIGHT' },
                    @{ Class = 'user'; Property = 'pwdLastSet'; Right = 'RP' },
                    @{ Class = 'user'; Property = 'pwdLastSet'; Right = 'WP' }
                )
            },
            @{
                ID = 103
                Description = 'Read all user information'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'user'; Property = '@'; Right = 'RP' }
                )
            },
            @{
                ID = 105
                Description = 'Create a user account in disabled state'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'scope'; Property = 'user'; Right = 'CC' }
                )
            },
            @{
                ID = 106
                Description = 'Create a user account'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'user'; Property = 'userAccountControl'; Right = 'WP' },
                    @{ Class = 'user'; Property = 'Reset Password'; Right = 'CONTROLRIGHT' },
                    @{ Class = 'scope'; Property = 'user'; Right = 'CC' }
                )
            },
            @{
                ID = 107
                Description = 'Delete a child user account'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'scope'; Property = 'user'; Right = 'DC' }
                )
            },
            @{
                ID = 108
                Description = 'Delete this user account'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'user'; Property = '@'; Right = 'SD' }
                )
            },
            @{
                ID = 109
                Description = 'Disable a user account'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'user'; Property = 'userAccountControl'; Right = 'WP' }
                )
            },
            @{
                ID = 110
                Description = 'Unlock a user account'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'user'; Property = 'lockoutTime'; Right = 'WP' }
                )
            },
            @{
                ID = 111
                Description = 'Enable a disabled user account'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'user'; Property = 'userAccountControl'; Right = 'WP' }
                )
            },
            @{
                ID = 112
                Description = 'Reset a user account`s password'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'user'; Property = 'Change Password'; Right = 'CONTROLRIGHT' }
                )
            },
            @{
                ID = 114
                Description = 'Modify a user`s display name'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'user'; Property = 'adminDisplayName'; Right = 'WP' }
                )
            },
            @{
                ID = 115
                Description = 'Modify a user account`s description'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'user'; Property = 'description'; Right = 'WP' }
                )
            },
            @{
                ID = 116
                Description = 'Modify a user`s office location'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'user'; Property = 'physicalDeliveryOfficeName'; Right = 'WP' }
                )
            },
            @{
                ID = 117
                Description = 'Modify a user`s telephone number'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'user'; Property = 'telephoneNumber'; Right = 'WP' }
                )
            },
            @{
                ID = 118
                Description = 'Modify the location of a user`s primary web page'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'user'; Property = 'wWWHomePage'; Right = 'WP' }
                )
            },
            @{
                ID = 119
                Description = 'Modify a user`s UPN'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'user'; Property = 'userPrincipalName'; Right = 'WP' }
                )
            },
            @{
                ID = 120
                Description = 'Modify a user`s Pre-Windows 2000 user logon name'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'user'; Property = 'sAMAccountName'; Right = 'WP' }
                )
            },
            @{
                ID = 121
                Description = 'Modify the hours during which a user can log on'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'user'; Property = 'logonHours'; Right = 'WP' }
                )
            },
            @{
                ID = 122
                Description = 'Specify the computers from which a user can log on'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'user'; Property = 'userWorkstations'; Right = 'WP' }
                )
            },
            @{
                ID = 123
                Description = 'Set Password Never Expires for a user account'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'user'; Property = 'userAccountControl'; Right = 'WP' }
                )
            },
            @{
                ID = 124
                Description = 'Set Store Password Using Reversible Encryption for a user account'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'user'; Property = 'userAccountControl'; Right = 'WP' }
                )
            },
            @{
                ID = 125
                Description = 'Disable a user account'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'user'; Property = 'userAccountControl'; Right = 'WP' }
                )
            },
            @{
                ID = 126
                Description = 'Set Smart card is required for interactive logon for a user account'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'user'; Property = 'userAccountControl'; Right = 'WP' }
                )
            },
            @{
                ID = 127
                Description = 'Set Account is sensitive and cannot be delegated for a user account'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'user'; Property = 'userAccountControl'; Right = 'WP' }
                )
            },
            @{
                ID = 128
                Description = 'Set Use DES encryption Classs for this account for a user account'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'user'; Property = 'userAccountControl'; Right = 'WP' }
                )
            },
            @{
                ID = 129
                Description = 'Set Do not require Kerberos pre-authentication for a user account'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'user'; Property = 'userAccountControl'; Right = 'WP' }
                )
            },
            @{
                ID = 130
                Description = 'Specify the date when a user account expires'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'user'; Property = 'accountExpires'; Right = 'WP' }
                )
            },
            @{
                ID = 131
                Description = 'Specify a profile path for a user'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'user'; Property = 'profilePath'; Right = 'WP' }
                )
            },
            @{
                ID = 132
                Description = 'Specify a logon script for a user'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'user'; Property = 'scriptPath'; Right = 'WP' }
                )
            },
            @{
                ID = 133
                Description = 'Rename a user account'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'user'; Property = 'cn'; Right = 'WP' },
                    @{ Class = 'user'; Property = 'name'; Right = 'WP' },
                    @{ Class = 'user'; Property = 'distinguishedName'; Right = 'WP' }
                )
            },

            #
            # GROUP
            #
            @{
                ID = 200
                Description = "`n--- GROUP ---`n"
            },
            @{
                ID = 200
                Description = 'Template 200: Create, delete and manage groups'
                AppliesTo = 'organizationalUnit,container'
                Template = @(
                    #@{ Class = 'group'; Property = '@'; Right = 'GA' },
                    @{ Class = 'group'; Property = '@'; Right = 'RP' },
                    @{ Class = 'group'; Property = '@'; Right = 'WP' },
                    @{ Class = 'scope'; Property = 'group'; Right = 'CC' },
                    @{ Class = 'scope'; Property = 'group'; Right = 'DC' }
                )
            },
            @{
                ID = 201
                Description = 'Template 201: Create a group'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'scope'; Property = 'group'; Right = 'CC' }
                )
            },
            @{
                ID = 204
                Description = 'Modify the membership of a group'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'group'; Property = 'member'; Right = 'RP' },
                    @{ Class = 'group'; Property = 'member'; Right = 'WP' }
                )
            },
            @{
                ID = 202
                Description = 'Template 202: Delete a child group'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'scope'; Property = 'group'; Right = 'DC' }
                )
            },
            @{
                ID = 203
                Description = 'Template 203: Delete this group'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'group'; Property = '@'; Right = 'SD' }
                )
            },
            @{
                ID = 204
                Description = 'Template 204: Rename a group'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'group'; Property = 'cn'; Right = 'WP' },
                    @{ Class = 'group'; Property = 'name'; Right = 'WP' }
                )
            },
            @{
                ID = 205
                Description = 'Template 205: Specify the Pre-Windows 2000 compatible name for the group'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'group'; Property = 'sAMAccountName'; Right = 'WP' }
                )
            },
            @{
                ID = 206
                Description = 'Template 206: Modify the description of a group'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'group'; Property = 'description'; Right = 'WP' }
                )
            },
            @{
                ID = 207
                Description = 'Template 207: Modify the scope of the group'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'group'; Property = 'groupClass'; Right = 'WP' }
                )
            },
            @{
                ID = 208
                Description = 'Template 208: Modify the Class of the group'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'group'; Property = 'groupClass'; Right = 'WP' }
                )
            },
            @{
                ID = 209
                Description = 'Template 209: Modify notes for a group'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'group'; Property = 'info'; Right = 'WP' }
                )
            },
            @{
                ID = 210
                Description = 'Template 210: Modify group membership'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'group'; Property = 'member'; Right = 'WP' }
                )
            },
            @{
                ID = 211
                Description = 'Template 211: Specify Managed-By Information of a Group'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'group'; Property = 'managedBy'; Right = 'WP' }
                )
            },

            #
            # COMPUTER
            #
            @{
                ID = 300
                Description = "`n--- COMPUTER ---`n"
            },
            @{
                ID = 300
                Description = 'Template 300: Join a computer to the domain'
                AppliesTo = 'domainDNS'
                Template = @(
                    @{ Class = 'scope'; Property = 'computer'; Right = 'CC' }
                )
            },
            @{
                ID = 301
                Description = 'Template 301: Create a computer account'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'scope'; Property = 'computer'; Right = 'CC' }
                )
            },
            @{
                ID = 302
                Description = 'Template 302: Delete a child computer account'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'scope'; Property = 'computer'; Right = 'DC' }
                )
            },
            @{
                ID = 303
                Description = 'Template 303: Delete this computer account'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'computer'; Property = '@'; Right = 'SD' }
                )
            },
            @{
                ID = 304
                Description = 'Template 304: Rename a computer account'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'computer'; Property = '@'; Right = 'WP' }
                )
            },
            @{
                ID = 305
                Description = 'Template 305: Disable a computer account'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'computer'; Property = 'userAccountControl'; Right = 'WP' }
                )
            },
            @{
                ID = 306
                Description = 'Template 306: Reset a computer account'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'computer'; Property = 'Reset Password'; Right = 'CONTROLRIGHT' }
                )
            },
            @{
                ID = 307
                Description = 'Template 307: Specify the computer`s description'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'computer'; Property = 'description'; Right = 'WP' }
                )
            },
            @{
                ID = 308
                Description = 'Template 308: Specify Managed-By information for a computer account'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'computer'; Property = 'managedBy'; Right = 'WP' }
                )
            },
            @{
                ID = 309
                Description = 'Template 309: Specify that a computer account be trusted for delegation'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'computer'; Property = 'userAccountControl'; Right = 'WP' }
                )
            },

            #
            # ORGANIZATIONAL UNIT
            #
            @{
                ID = 400
                Description = "`n--- ORGANIZATIONAL UNIT ---`n"
            },
            @{
                ID = 400
                Description = 'Template 400: Create an Organizational Unit'
                AppliesTo = 'domainDNS,organizationalUnit'
                Template = @(
                    @{ Class = 'scope'; Property = 'organizationalUnit'; Right = 'CC' }
                )
            },
            @{
                ID = 401
                Description = 'Template 401: Delete a child Organizational Unit'
                AppliesTo = 'domainDNS,organizationalUnit'
                Template = @(
                    @{ Class = 'scope'; Property = 'organizationalUnit'; Right = 'DC' }
                )
            },
            @{
                ID = 402
                Description = 'Template 402: Delete this Organizational Unit'
                AppliesTo = 'organizationalUnit'
                Template = @(
                    @{ Class = 'organizationalUnit'; Property = '@'; Right = 'SD' }
                )
            },
            @{
                ID = 403
                Description = 'Template 403: Rename an Organizational Unit'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'organizationalUnit'; Property = 'ou'; Right = 'WP' },
                    @{ Class = 'organizationalUnit'; Property = 'name'; Right = 'WP' }
                )
            },
            @{
                ID = 404
                Description = 'Template 404: Modify Description of an Organizational Unit'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'organizationalUnit'; Property = 'description'; Right = 'WP' }
                )
            },
            @{
                ID = 405
                Description = 'Template 405: Modify Managed-By Information of an Organizational Unit'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'organizationalUnit'; Property = 'managedBy'; Right = 'WP' }
                )
            },
            @{
                ID = 406
                Description = 'Template 406: Delegate Control of an Organizational Unit'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'organizationalUnit'; Property = '@'; Right = 'WD' }
                )
            },

            #
            # INETORGPERSON
            #
            @{
                ID = 500
                Description = "`n--- INETORGPERSON ---`n"
            },
            @{
                ID = 500
                Description = 'Template 500: Create, delete, and manage inetOrgPerson accounts'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    #@{ Class = 'inetOrgPerson'; Property = '@'; Right = 'GA' },
                    @{ Class = 'inetOrgPerson'; Property = '@'; Right = 'RP' },
                    @{ Class = 'inetOrgPerson'; Property = '@'; Right = 'WP' },
                    @{ Class = 'scope'; Property = 'inetOrgPerson'; Right = 'CC' },
                    @{ Class = 'scope'; Property = 'inetOrgPerson'; Right = 'DC' }
                )
            },
            @{
                ID = 501
                Description = 'Template 501: Reset inetOrgPerson passwords and force password change at next logon'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'inetOrgPerson'; Property = 'Reset Password'; Right = 'CONTROLRIGHT' },
                    @{ Class = 'inetOrgPerson'; Property = 'pwdLastSet'; Right = 'RP' },
                    @{ Class = 'inetOrgPerson'; Property = 'pwdLastSet'; Right = 'WP' }
                )
            },
            @{
                ID = 502
                Description = 'Template 502: Read all inetOrgPerson information'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'inetOrgPerson'; Property = '@'; Right = 'RP' }
                )
            },

            #
            # GROUP POLICY
            #
            @{
                ID = 600
                Description = "`n--- GROUP POLICY ---`n"
            },
            @{
                ID = 600
                Description = 'Template 600: Manage Group Policy links'
                AppliesTo = 'domainDNS,organizationalUnit,site'
                Template = @(
                    @{ Class = 'scope'; Property = 'gPLink'; Right = 'RP' },
                    @{ Class = 'scope'; Property = 'gPLink'; Right = 'WP' },
                    @{ Class = 'scope'; Property = 'gPOptions'; Right = 'RP' },
                    @{ Class = 'scope'; Property = 'gPOptions'; Right = 'WP' }
                )
            },
            @{
                ID = 601
                Description = 'Template 601: Generate Resultant Set of Policy (Planning)'
                AppliesTo = 'domainDNS,organizationalUnit'
                Template = @(
                    @{ Class = 'scope'; Property = 'Generate Resultant Set of Policy (Planning)'; Right = 'CONTROLRIGHT' }
                )
            },
            @{
                ID = 602
                Description = 'Template 602: Generate Resultant Set of Policy (Logging)'
                AppliesTo = 'domainDNS,organizationalUnit'
                Template = @(
                    @{ Class = 'scope'; Property = 'Generate Resultant Set of Policy (Logging)'; Right = 'CONTROLRIGHT' }
                )
            },

            #
            # WMI FILTER
            #
            @{
                ID = 700
                Description = "`n--- WMI FILTERS ---`n"
            }
            @{
                ID = 700
                Description = 'Template 700: Create, Delete, and Manage WMI Filters'
                AppliesTo = 'container'
                Template = @(
                    #@{ Class = 'msWMI-Som'; Property = '@'; Right = 'GA' },
                    @{ Class = 'msWMI-Som'; Property = '@'; Right = 'RP' },
                    @{ Class = 'msWMI-Som'; Property = '@'; Right = 'WP' },
                    @{ Class = 'scope'; Property = 'msWMI-Som'; Right = 'CC' },
                    @{ Class = 'scope'; Property = 'msWMI-Som'; Right = 'DC' }
                )
            }
        )
        
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

                [Parameter()]
                [string]$AppliesTo = $null
            )
            
            $adObject = [ADSI]"LDAP://$ObjectPathDN"
            $ace = $null
            
            # Check if the object should applies to the current object class
            if($AppliesTo){
                $adSchemaObject = $adObject.SchemaClassName
                [string[]]$appliesToArray = $AppliesTo.split(',')

                if($appliesToArray -notcontains $adSchemaObject){
                    Write-Warning -Message "[WARN] The Template is not supposed to apply on this ObjectClass $adSchemaObject"
                }
            }
            
            # BUILD Access Control Entry 
            if($ClassGUID -eq 0) {
                # SCOPE
                $ace = New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList (
                    [System.Security.Principal.NTAccount]$Identity, 
                    [System.DirectoryServices.ActiveDirectoryRights]$Rights,
                    [System.Security.AccessControl.AccessControlType]::Allow,
                    [GUID]$PropertyGUID,
                    [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
                )
            }
            else
            {
                # CLASS
                If($PropertyGUID -eq 0) {
                    # @
                    $ace = New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList (
                        [System.Security.Principal.NTAccount]$Identity, 
                        [System.DirectoryServices.ActiveDirectoryRights]$Rights,
                        [System.Security.AccessControl.AccessControlType]::Allow,
                        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,
                        [GUID]$ClassGUID
                    )
                }
                else
                {
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
            
            $verboseMessage = "[*] Applied permission:`n`t=> ADIdentity = $Identity,`n`t=> OU = $ObjectPathDN,`n`t=> Right = $Rights,`n`t=> Object Class GUID = $ClassGUID,`n`t=> Property GUID = $PropertyGUID"
            Write-Verbose -Message $verboseMessage
        }

        # Show all templates
        function Show-Templates([switch]$IncludeDetails) {
            for ($i = 0; $i -lt $delegationTemplates.Count; $i++) {
                $template = $delegationTemplates[$i]

                # Show Template Categorie
                if($template.ID -like "*00") {
                    Write-Host -Object $template.Description
                    continue
                }

                Write-Host -Object ("Template {0}: {1}" -f $template.ID, $template.Description)
                if($IncludeDetails) {
                    if ($template.AppliesTo) {
                        Write-Host "   AppliesTo: $($template.AppliesTo)"
                    }
                    if ($template.Template) {
                        Write-Host "   Rules:"
                        foreach ($rule in $template.Template) {
                            Write-Host "`tClass: $($rule.Class) | Property: $($rule.Property) | Right: $($rule.Right)"
                        }
                    }
                }
            }
        }

        # Show a list of templates of a selected category
        function Show-TemplateCategory([int]$CategoryStart = 0) {

            [decimal]$nextHundred = [math]::Ceiling(($CategoryStart + 1) / 100) * 100
            $categorieTemplates = $delegationTemplates | Where-Object {($_.ID -ge $CategoryStart) -and ($_.ID -lt $nextHundred)}

            for ($i = 0; $i -lt $categorieTemplates.Count; $i++) {
                Write-Host -Object "$($categorieTemplates[$i].Description)"
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
                [string]$PropertyGUID = $null
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
    }
    
    process {

        # Show Templates
        if ($PSCmdlet.ParameterSetName -like 'Viewer') {
            if ($ShowTemplates)              { Show-Templates; continue }
			if ($ShowTemplatesDetailed)      { Show-Templates -IncludeDetails; continue }
            if ($ShowUserTemplates)          { Show-TemplateCategory -CategoryStart 100 }
            if ($ShowGroupTemplates)         { Show-TemplateCategory -CategoryStart 200 }
            if ($ShowComputerTemplates)      { Show-TemplateCategory -CategoryStart 300 }
            if ($ShowOUTemplates)            { Show-TemplateCategory -CategoryStart 400 }
            if ($ShowInetOrgPersonTemplates) { Show-TemplateCategory -CategoryStart 500 }
            if ($ShowGPOTemplates)           { Show-TemplateCategory -CategoryStart 600 }
            if ($ShowWmiTemplates)           { Show-TemplateCategory -CategoryStart 700 }

            continue
        }

        # Parameter validation
        if($LogChanges) {
            if(-not $LogPath) {
                Write-Error -Message '[err] No valid LogPath-Param found!'
                continue
            }
        }

        # Do the Job...
        try {
            
            # Apply multiple Templates
            Foreach($templateID in $TemplateIDs) {
                
                # Get Template
                $selectedTemplate = $delegationTemplates | Where-Object {$_.ID -eq $templateID} 
                
                if($null -eq $selectedTemplate){
                    # No Template found!
                    Write-Warning -Message "[warn] No template with ID $($templateID.ToString()) found!"
                    break
                }                
                
                # Apply multiple template Permission Rules
                Foreach($rule in $selectedTemplate.Template) {
                
                    # Mapping Name to GUID
                    $propertyGUID = ''
                    if($rule.Class -like 'scope')
                    {
                        $propertyGUID = $classGuidsMap[$rule.Property]
                    }
                    else
                    {
                        $propertyGUID = $propertyGuidsMap[$rule.Property]
                    }
                
                    $params = @{
                        'Identity' =      $AdIdentity
                        'ObjectPathDN' =  $AdObjectPathDN
                        'ClassGUID' =     $classGuidsMap[$rule.Class]
                        'PropertyGUID' =  $propertyGUID
                        'Right' =         $rightsMap[$rule.Right]
                        'AppliesTo' =     $selectedTemplate.AppliesTo
                    }
                
                    # Set Permissions to Object
                    Grant-AdPermission @params
                
                    # Log changes
                    if ($LogChanges) {
                        if ($null -eq $LogPath) {
                            Write-Error -Message '[err] No LogPath found. Please Enter a valid -LogPath'
                        }
                        else {
                            Write-PermissionChangesToLog -TemplateID $templateID -LogFilePath $LogPath @params
                        }
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
}
