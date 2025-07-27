#requires -Version 3.0

<#
    Author: Jan Weis
    Version: v1.2
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
        [string]$LogPath = "$env:USERPROFILE\Documents\DelegationTemplateChanges.txt",

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
            'GA' = [DirectoryServices.ActiveDirectoryRights]::GenericAll
            'GE' = [DirectoryServices.ActiveDirectoryRights]::GenericExecute
            'GR' = [DirectoryServices.ActiveDirectoryRights]::GenericRead
            'GW' = [DirectoryServices.ActiveDirectoryRights]::GenericWrite
            'SD' = [DirectoryServices.ActiveDirectoryRights]::Self
            'LC' = [DirectoryServices.ActiveDirectoryRights]::ListChildren
            'LO' = [DirectoryServices.ActiveDirectoryRights]::ListObject
            'CC' = [DirectoryServices.ActiveDirectoryRights]::CreateChild
            'DC' = [DirectoryServices.ActiveDirectoryRights]::DeleteChild
            'DT' = [DirectoryServices.ActiveDirectoryRights]::DeleteTree
            'RC' = [DirectoryServices.ActiveDirectoryRights]::ReadControl
            'RP' = [DirectoryServices.ActiveDirectoryRights]::ReadProperty
            'WD' = [DirectoryServices.ActiveDirectoryRights]::WriteDacl
            'WO' = [DirectoryServices.ActiveDirectoryRights]::WriteOwner
            'WP' = [DirectoryServices.ActiveDirectoryRights]::WriteProperty
            'CONTROLRIGHT' = [DirectoryServices.ActiveDirectoryRights]::ExtendedRight
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
                Description = "n----- USER -----n"
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
                ID = 104
                Description = 'Create a user account in disabled state'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'scope'; Property = 'user'; Right = 'CC' }
                )
            },
            @{
                ID = 105
                Description = 'Create a user account'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'user'; Property = 'userAccountControl'; Right = 'WP' },
                    @{ Class = 'user'; Property = 'Reset Password'; Right = 'CONTROLRIGHT' },
                    @{ Class = 'scope'; Property = 'user'; Right = 'CC' }
                )
            },
            @{
                ID = 106
                Description = 'Delete a child user account'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'scope'; Property = 'user'; Right = 'DC' }
                )
            },
            @{
                ID = 107
                Description = 'Delete this user account'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'user'; Property = '@'; Right = 'SD' }
                )
            },
            @{
                ID = 108
                Description = 'Disable a user account'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'user'; Property = 'userAccountControl'; Right = 'WP' }
                )
            },
            @{
                ID = 109
                Description = 'Unlock a user account'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'user'; Property = 'lockoutTime'; Right = 'WP' }
                )
            },
            @{
                ID = 110
                Description = 'Rename a user account'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'user'; Property = 'cn'; Right = 'WP' },
                    @{ Class = 'user'; Property = 'name'; Right = 'WP' },
                    @{ Class = 'user'; Property = 'distinguishedName'; Right = 'WP' }
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
                Description = 'Reset a user accounts password'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'user'; Property = 'Change Password'; Right = 'CONTROLRIGHT' }
                )
            },
            @{
                ID = 114
                Description = 'Modify a users display name'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'user'; Property = 'adminDisplayName'; Right = 'WP' }
                )
            },
            @{
                ID = 115
                Description = 'Modify a user accounts description'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'user'; Property = 'description'; Right = 'WP' }
                )
            },
            @{
                ID = 116
                Description = 'Modify a users office location'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'user'; Property = 'physicalDeliveryOfficeName'; Right = 'WP' }
                )
            },
            @{
                ID = 117
                Description = 'Modify a users telephone number'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'user'; Property = 'telephoneNumber'; Right = 'WP' }
                )
            },
            @{
                ID = 118
                Description = 'Modify the location of a users primary web page'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'user'; Property = 'wWWHomePage'; Right = 'WP' }
                )
            },
            @{
                ID = 119
                Description = 'Modify a users UPN'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'user'; Property = 'userPrincipalName'; Right = 'WP' }
                )
            },
            @{
                ID = 120
                Description = 'Modify a users Pre-Windows 2000 user logon name'
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


            #
            # GROUP
            #
            @{
                ID = 200
                Description = "n--- GROUP ---n"
            },
            @{
                ID = 201
                Description = 'Create, delete and manage groups'
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
                ID = 202
                Description = 'Create a group'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'scope'; Property = 'group'; Right = 'CC' }
                )
            },
            @{
                ID = 203
                Description = 'Modify the membership of a group'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'group'; Property = 'member'; Right = 'RP' },
                    @{ Class = 'group'; Property = 'member'; Right = 'WP' }
                )
            },
            @{
                ID = 204
                Description = 'Delete a child group'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'scope'; Property = 'group'; Right = 'DC' }
                )
            },
            @{
                ID = 205
                Description = 'Delete this group'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'group'; Property = '@'; Right = 'SD' }
                )
            },
            @{
                ID = 206
                Description = 'Rename a group'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'group'; Property = 'cn'; Right = 'WP' },
                    @{ Class = 'group'; Property = 'name'; Right = 'WP' }
                )
            },
            @{
                ID = 207
                Description = 'Specify the Pre-Windows 2000 compatible name for the group'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'group'; Property = 'sAMAccountName'; Right = 'WP' }
                )
            },
            @{
                ID = 208
                Description = 'Modify the description of a group'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'group'; Property = 'description'; Right = 'WP' }
                )
            },
            @{
                ID = 209
                Description = 'Modify the scope of the group'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'group'; Property = 'groupClass'; Right = 'WP' }
                )
            },
            @{
                ID = 210
                Description = 'Modify the Class of the group'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'group'; Property = 'groupClass'; Right = 'WP' }
                )
            },
            @{
                ID = 211
                Description = 'Modify notes for a group'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'group'; Property = 'info'; Right = 'WP' }
                )
            },
            @{
                ID = 212
                Description = 'Modify group membership'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'group'; Property = 'member'; Right = 'WP' }
                )
            },
            @{
                ID = 213
                Description = 'Specify Managed-By Information of a Group'
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
                Description = "n--- COMPUTER ---n"
            },
            @{
                ID = 301
                Description = 'Join a computer to the domain'
                AppliesTo = 'domainDNS'
                Template = @(
                    @{ Class = 'scope'; Property = 'computer'; Right = 'CC' }
                )
            },
            @{
                ID = 302
                Description = 'Create a computer account'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'scope'; Property = 'computer'; Right = 'CC' }
                )
            },
            @{
                ID = 303
                Description = 'Delete a child computer account'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'scope'; Property = 'computer'; Right = 'DC' }
                )
            },
            @{
                ID = 304
                Description = 'Delete this computer account'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'computer'; Property = '@'; Right = 'SD' }
                )
            },
            @{
                ID = 305
                Description = 'Rename a computer account'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'computer'; Property = '@'; Right = 'WP' }
                )
            },
            @{
                ID = 306
                Description = 'Disable a computer account'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'computer'; Property = 'userAccountControl'; Right = 'WP' }
                )
            },
            @{
                ID = 307
                Description = 'Reset a computer account'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'computer'; Property = 'Reset Password'; Right = 'CONTROLRIGHT' }
                )
            },
            @{
                ID = 308
                Description = 'Specify the computers description'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'computer'; Property = 'description'; Right = 'WP' }
                )
            },
            @{
                ID = 309
                Description = 'Specify Managed-By information for a computer account'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'computer'; Property = 'managedBy'; Right = 'WP' }
                )
            },
            @{
                ID = 310
                Description = 'Specify that a computer account be trusted for delegation'
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
                Description = "n--- ORGANIZATIONAL UNIT ---n"
            },
            @{
                ID = 401
                Description = 'Create an Organizational Unit'
                AppliesTo = 'domainDNS,organizationalUnit'
                Template = @(
                    @{ Class = 'scope'; Property = 'organizationalUnit'; Right = 'CC' }
                )
            },
            @{
                ID = 402
                Description = 'Delete a child Organizational Unit'
                AppliesTo = 'domainDNS,organizationalUnit'
                Template = @(
                    @{ Class = 'scope'; Property = 'organizationalUnit'; Right = 'DC' }
                )
            },
            @{
                ID = 403
                Description = 'Delete this Organizational Unit'
                AppliesTo = 'organizationalUnit'
                Template = @(
                    @{ Class = 'organizationalUnit'; Property = '@'; Right = 'SD' }
                )
            },
            @{
                ID = 404
                Description = 'Rename an Organizational Unit'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'organizationalUnit'; Property = 'ou'; Right = 'WP' },
                    @{ Class = 'organizationalUnit'; Property = 'name'; Right = 'WP' }
                )
            },
            @{
                ID = 405
                Description = 'Modify Description of an Organizational Unit'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'organizationalUnit'; Property = 'description'; Right = 'WP' }
                )
            },
            @{
                ID = 406
                Description = 'Modify Managed-By Information of an Organizational Unit'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'organizationalUnit'; Property = 'managedBy'; Right = 'WP' }
                )
            },
            @{
                ID = 407
                Description = 'Delegate Control of an Organizational Unit'
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
                Description = "n--- INETORGPERSON ---n"
            },
            @{
                ID = 501
                Description = 'Create, delete, and manage inetOrgPerson accounts'
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
                ID = 502
                Description = 'Reset inetOrgPerson passwords and force password change at next logon'
                AppliesTo = 'domainDNS,organizationalUnit,container'
                Template = @(
                    @{ Class = 'inetOrgPerson'; Property = 'Reset Password'; Right = 'CONTROLRIGHT' },
                    @{ Class = 'inetOrgPerson'; Property = 'pwdLastSet'; Right = 'RP' },
                    @{ Class = 'inetOrgPerson'; Property = 'pwdLastSet'; Right = 'WP' }
                )
            },
            @{
                ID = 503
                Description = 'Read all inetOrgPerson information'
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
                Description = "n--- GROUP POLICY ---n"
            },
            @{
                ID = 601
                Description = 'Manage Group Policy links'
                AppliesTo = 'domainDNS,organizationalUnit,site'
                Template = @(
                    @{ Class = 'scope'; Property = 'gPLink'; Right = 'RP' },
                    @{ Class = 'scope'; Property = 'gPLink'; Right = 'WP' },
                    @{ Class = 'scope'; Property = 'gPOptions'; Right = 'RP' },
                    @{ Class = 'scope'; Property = 'gPOptions'; Right = 'WP' }
                )
            },
            @{
                ID = 602
                Description = 'Generate Resultant Set of Policy (Planning)'
                AppliesTo = 'domainDNS,organizationalUnit'
                Template = @(
                    @{ Class = 'scope'; Property = 'Generate Resultant Set of Policy (Planning)'; Right = 'CONTROLRIGHT' }
                )
            },
            @{
                ID = 603
                Description = 'Generate Resultant Set of Policy (Logging)'
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
                Description = "n--- WMI FILTERS ---n"
            }
            @{
                ID = 701
                Description = 'Create, Delete, and Manage WMI Filters'
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
                [DirectoryServices.ActiveDirectoryRights]$Rights,

                [string]$AppliesTo = ''
            )
            
            $adObject = [ADSI]"LDAP://$ObjectPathDN"
            $ace = $null
            
            # Check if the object should applies to the current object class
            if($AppliesTo){
                $adSchemaObject = $adObject.SchemaClassName
                [string[]]$appliesToArray = $AppliesTo.split(',')

                if($appliesToArray -notcontains $adSchemaObject){
                    Write-Warning -Message "[WARN] The Template is not supposed to apply on this ObjectClass."
                }
            }
            
            # BUILD Access Control Entry 
            if($ClassGUID -eq 0) {
                # SCOPE
                $ace = New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList (
                    [Security.Principal.NTAccount]$Identity, 
                    [DirectoryServices.ActiveDirectoryRights]$Rights,
                    [Security.AccessControl.AccessControlType]::Allow,
                    [GUID]$PropertyGUID,
                    [DirectoryServices.ActiveDirectorySecurityInheritance]::All
                )
            }
            else
            {
                # CLASS
                If($PropertyGUID -eq 0) {
                    # @
                    $ace = New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList (
                        [Security.Principal.NTAccount]$Identity, 
                        [DirectoryServices.ActiveDirectoryRights]$Rights,
                        [Security.AccessControl.AccessControlType]::Allow,
                        [DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,
                        [GUID]$ClassGUID
                    )
                }
                else
                {
                    # PROPERTY
                    $ace = New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList (
                        [Security.Principal.NTAccount]$Identity, 
                        [DirectoryServices.ActiveDirectoryRights]$Rights,
                        [Security.AccessControl.AccessControlType]::Allow,
                        [GUID]$PropertyGUID,
                        [DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,
                        [GUID]$ClassGUID
                    )
                }
            }

            $adObject.ObjectSecurity.AddAccessRule($ace)    
            $adObject.CommitChanges()
            
            $verboseMessage = "[*] Applied permission:nt=> ADIdentity = $Identity,nt=> OU = $ObjectPathDN,nt=> Right = $Rights,nt=> Object Class GUID = $ClassGUID,nt=> Property GUID = $PropertyGUID"
            Write-Verbose -Message $verboseMessage
        }

        # Show all templates
        function Show-Templates([switch]$IncludeDetails) {
            for ($i = 0; $i -lt $delegationTemplates.Count; $i++) {
                $template = $delegationTemplates[$i]

                # Show only Template Categorie
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
                            Write-Host "tClass: $($rule.Class) | Property: $($rule.Property) | Right: $($rule.Right)"
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
                if($categorieTemplates[$i].ID -like "*00") {
                    Write-Host -Object $categorieTemplates[$i].Description
                    continue
                }

                Write-Host -Object ("Template {0}: {1}" -f $categorieTemplates[$i].ID, $categorieTemplates[$i].Description)
            }
        }

        # Writes a Logging for Changes, to revert Changes easyly
        function Write-PermissionChangesToLog {
            param (
                [Parameter(Mandatory)]
                [PSCustomObject]$LogInput,

                [Parameter(Mandatory)]
                [string]$TemplateID,

                [Parameter(Mandatory)]
                [string]$Path
            )

            $tempInput = $LogInput
            $tempInput | Add-Member -MemberType NoteProperty -Name TemplateID -Value $TemplateID
            $tempInput | Add-Member -MemberType NoteProperty -Name Date -Value (Get-Date).ToShortDateString()
            $tempInput | Add-Member -MemberType NoteProperty -Name Time -Value (Get-Date).ToShortTimeString()

            try {
                Export-Csv -InputObject $tempInput -Path $Path -Delimiter ";" -NoTypeInformation -Encoding UTF8
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
                    }
                
                    # Set Permissions to Object
                    Grant-AdPermission @params -AppliesTo $selectedTemplate.AppliesTo
                
                    # Log changes
                    if ($LogChanges) {
                        if ($null -eq $LogPath) {
                            Write-Error -Message '[err] No LogPath found. Please Enter a valid -LogPath'
                        }
                        else {
                            Write-PermissionChangesToLog -LogInput ([PSCustomObject]$params) -TemplateID $selectedTemplate.ID -Path $LogPath
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
