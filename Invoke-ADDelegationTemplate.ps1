#requires -Version 3.0
#requires -modules ActiveDirectory

#
# Author: Jan Weis
# Version: 1.0
# Web: www.it-explorations.de
#

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

Invoke-ADDelegationTemplate -AdIdentity UserManagerPermissionGroup -DelegationOuDN "OU=MySpecialOU,DC=ad,DC=MyADDomain,DC=de" -TemplateID 101
#>
function Invoke-ADDelegationTemplate {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ParameterSetName = "DoTheMagic")]
        [string]$AdIdentity,

        [Parameter(Mandatory, ParameterSetName = "DoTheMagic")]
        [string]$DelegationOuDN,

        [Parameter(Mandatory, ParameterSetName = "DoTheMagic")]
        [int]$TemplateID,

        [Parameter(Mandatory, ParameterSetName = "Viewer")]
        [switch]$ShowTemplates
    )
    
    begin {
        Write-Verbose -Message "[Invoke-ADDelegationTemplate] START"

        function Grant-AdPermission {
            param (
                [Parameter(Mandatory)]
                [string]$Identity,
            
                [Parameter(Mandatory)]
                [string]$OrganizationalUnitDN,
                
                [Parameter(Mandatory)]
                [System.DirectoryServices.ActiveDirectoryRights]$Rights,
                
                [string]$ObjectTypeGUID = $null,
                [string]$ControlRight = $null,
                [string]$PropertyGUID = $null
            )

            $adObject = [ADSI]"LDAP://$OrganizationalUnitDN"

            if ($ControlRight) {
                $ace = New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList (
                    [System.Security.Principal.NTAccount]$Identity, 
                    [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight, 
                    [System.Security.AccessControl.AccessControlType]::Allow, 
                    [guid]$ControlRight
                )
            }
            elseif ($PropertyGUID) {
                $ace = New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList (
                    [System.Security.Principal.NTAccount]$Identity, 
                    [System.DirectoryServices.ActiveDirectoryRights]$Rights,
                    [System.Security.AccessControl.AccessControlType]::Allow, 
                    [guid]$PropertyGUID,
                    [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,
                    [guid]$ObjectTypeGUID
                )
            }
            else {
                $ace = New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList (
                    [System.Security.Principal.NTAccount]$Identity, 
                    [System.DirectoryServices.ActiveDirectoryRights]$Rights, 
                    [System.Security.AccessControl.AccessControlType]::Allow,
                    [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,
                    [guid]$ObjectTypeGUID
                )
            }

            $adObject.ObjectSecurity.AddAccessRule($ace)    
            $adObject.CommitChanges()
            Write-Verbose -Message "[*] Applied permission: Rights = $Rights, Object Type GUID = $ObjectTypeGUID, Control Right = $ControlRight, Property GUID = $PropertyGUID to OU = $OrganizationalUnitDN for Group = $ADGroupDN"
        }

        function Select-Template {
            param (
                [Parameter(Mandatory)]
                [array]$Templates,

                [Parameter(Mandatory)]
                [int]$TemplateID
            )

            return $Templates[$TemplateID - 1]
        }

        function Show-Templates() {
            for ($i = 0; $i -lt $templates.Count; $i++) {
                Write-Host -Object "$($templates[$i].Description)"
            }
        }

        #
        # GUIDs for objects
        #
        $userObjectGUID = 'bf967aba-0de6-11d0-a285-00aa003049e2'
        $groupObjectGUID = 'bf967a9c-0de6-11d0-a285-00aa003049e2'
        $computerObjectGUID = 'bf967a86-0de6-11d0-a285-00aa003049e2'
        $ouObjectGUID = 'bf967aa5-0de6-11d0-a285-00aa003049e2'
        $inetOrgPersonObjectGUID = '4828cc14-1437-45bc-9b07-ad6f015e5f28'
        $wmiFilterObjectGUID = '17b8b2f3-35e1-4c7c-b9b0-dba7750c9e4d'
        $gpLinkObjectGUID = 'f30e3bbe-9ff0-11d1-b603-0000f80367c1'
        $gpOptionsObjectGUID = 'f30e3bbf-9ff0-11d1-b603-0000f80367c1'

        #
        # GUIDs for control rights
        #
        $resetPasswordGUID = '00299570-246d-11d0-a768-00aa006e0529'
        $changePasswordGUID = 'ab721a53-1e2f-11d0-9819-00aa0040529b'
        $rsopPlanningGUID = 'b7b1b3dd-ab09-4242-9e30-9980e5d322f7'
        $rsopLoggingGUID = 'b7b1b3de-ab09-4242-9e30-9980e5d322f7'

        #
        # GUIDs for properties
        #
        ## COMMON properties
        $cnPropertyGUID = 'bf96793f-0de6-11d0-a285-00aa003049e2'
        $namePropertyGUID = 'bf967a0e-0de6-11d0-a285-00aa003049e2'
        $displayNamePropertyGUID = 'bf967953-0de6-11d0-a285-00aa003049e2'
        $sAMAccountNamePropertyGUID = '3e0abfd0-126a-11d0-a060-00aa006c33ed'
        $userAccountControlPropertyGUID = 'bf967a68-0de6-11d0-a285-00aa003049e2'
        $descriptionPropertyGUID = 'bf967950-0de6-11d0-a285-00aa003049e2'
        $infoPropertyGUID = 'bf96793e-0de6-11d0-a285-00aa003049e2'
        $managedByPropertyGUID = '0296c120-40da-11d1-a9c0-0000f80367c1'
        $telephoneNumberPropertyGUID = 'bf967a49-0de6-11d0-a285-00aa003049e2'
        $wWWHomePagePropertyGUID = 'bf967a7a-0de6-11d0-a285-00aa003049e2'
        
        ## USER properties
        $userPrincipalNamePropertyGUID = '28630ebb-41d5-11d1-a9c1-0000f80367c1'
        $accountExpiresPropertyGUID = 'bf967915-0de6-11d0-a285-00aa003049e2'
        $lockoutTimePropertyGUID = '28630ebf-41d5-11d1-a9c1-0000f80367c1'
        $pwdLastSetPropertyGUID = 'bf967a0a-0de6-11d0-a285-00aa003049e2'
        $physicalDeliveryOfficeNamePropertyGUID = 'bf9679f7-0de6-11d0-a285-00aa003049e2'
        $logonHoursPropertyGUID = 'bf9679ab-0de6-11d0-a285-00aa003049e2'
        $userWorkstationsPropertyGUID = 'bf9679d7-0de6-11d0-a285-00aa003049e2'
        $profilePathPropertyGUID = 'bf967a05-0de6-11d0-a285-00aa003049e2'
        $scriptPathPropertyGUID = 'bf9679a8-0de6-11d0-a285-00aa003049e2'
        $ouPropertyGUID = 'bf9679f0-0de6-11d0-a285-00aa003049e2'
        
        ## GROUP properties
        $memberPropertyGUID = 'bf9679c0-0de6-11d0-a285-00aa003049e2'
        $groupTypePropertyGUID = '9a9a021e-4a5b-11d1-a9c3-0000f80367c1'
        

        # Template configurations
        $templates = @(

            #
            # User Account Templates
            #
            @{
                ID          = 100
                Description = "`n --- User Account Templates ---"
                #Rights         = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
                #ObjectTypeGUID = $userObjectGUID
            }, 
            @{
                ID             = 101
                Description    = 'Template 101: Create, delete, and manage user accounts'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
                ObjectTypeGUID = $userObjectGUID
            }, 
            @{
                ID           = 102
                Description  = 'Template 102: Reset user passwords and force password change at next logon'
                Rights       = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
                ControlRight = $resetPasswordGUID
            }, 
            @{
                ID             = 103
                Description    = 'Template 103: Read all user information'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty
                ObjectTypeGUID = $userObjectGUID
            }, 
            @{
                ID             = 104
                Description    = 'Template 104: Create a user account in disabled state'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::CreateChild
                ObjectTypeGUID = $userObjectGUID
            }, 
            @{
                ID             = 105
                Description    = 'Template 105: Create a user account'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::CreateChild
                ObjectTypeGUID = $userObjectGUID
                PropertyGUID   = $userAccountControlPropertyGUID
                ControlRight   = $resetPasswordGUID
            }, 
            @{
                ID             = 106
                Description    = 'Template 106: Delete a child user account'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild
                ObjectTypeGUID = $userObjectGUID
            }, 
            @{
                ID             = 107
                Description    = 'Template 107: Delete this user account'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::Delete
                ObjectTypeGUID = $userObjectGUID
            }, 
            @{
                ID             = 108
                Description    = 'Template 108: Rename a user account'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
                ObjectTypeGUID = $userObjectGUID
                PropertyGUID   = $cnPropertyGUID
            }, 
            @{
                ID             = 109
                Description    = 'Template 109: Rename a user account (Name)'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
                ObjectTypeGUID = $userObjectGUID
                PropertyGUID   = $namePropertyGUID
            }, 
            @{
                ID             = 110
                Description    = 'Template 110: Rename a user account (distinguishedName)'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
                ObjectTypeGUID = $userObjectGUID
                PropertyGUID   = $userObjectGUID
            }, 
            @{
                ID             = 111
                Description    = 'Template 111: Disable a user account'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
                ObjectTypeGUID = $userObjectGUID
                PropertyGUID   = $userAccountControlPropertyGUID
            }, 
            @{
                ID             = 112
                Description    = 'Template 112: Unlock a user account'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
                ObjectTypeGUID = $userObjectGUID
                PropertyGUID   = $lockoutTimePropertyGUID
            }, 
            @{
                ID             = 113
                Description    = 'Template 113: Enable a disabled user account'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
                ObjectTypeGUID = $userObjectGUID
                PropertyGUID   = $userAccountControlPropertyGUID
            }, 
            @{
                ID           = 114
                Description  = "Template 114: Reset a user account's password"
                Rights       = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
                ControlRight = $changePasswordGUID
            }, 
            @{
                ID           = 115
                Description  = 'Template 115: Force a user account to change the password at the next logon'
                Rights       = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
                ControlRight = $resetPasswordGUID
                PropertyGUID = $pwdLastSetPropertyGUID
            }, 
            @{
                ID             = 116
                Description    = "Template 116: Modify a user's display name"
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
                ObjectTypeGUID = $userObjectGUID
                PropertyGUID   = $displayNamePropertyGUID
            }, 
            @{
                ID             = 117
                Description    = "Template 117: Modify a user account's description"
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
                ObjectTypeGUID = $userObjectGUID
                PropertyGUID   = $descriptionPropertyGUID
            }, 
            @{
                ID             = 118
                Description    = "Template 118: Modify a user's office location"
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
                ObjectTypeGUID = $userObjectGUID
                PropertyGUID   = $physicalDeliveryOfficeNamePropertyGUID
            }, 
            @{
                ID             = 119
                Description    = "Template 119: Modify a user's telephone number"
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
                ObjectTypeGUID = $userObjectGUID
                PropertyGUID   = $telephoneNumberPropertyGUID
            }, 
            @{
                ID             = 120
                Description    = "Template 120: Modify the location of a user's primary web page"
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
                ObjectTypeGUID = $userObjectGUID
                PropertyGUID   = $wWWHomePagePropertyGUID
            }, 
            @{
                ID             = 121
                Description    = "Template 121: Modify a user's UPN"
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
                ObjectTypeGUID = $userObjectGUID
                PropertyGUID   = $userPrincipalNamePropertyGUID
            }, 
            @{
                ID             = 122
                Description    = "Template 122: Modify a user's Pre-Windows 2000 user logon name"
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
                ObjectTypeGUID = $userObjectGUID
                PropertyGUID   = $sAMAccountNamePropertyGUID
            }, 
            @{
                ID             = 123
                Description    = 'Template 123: Modify the hours during which a user can log on'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
                ObjectTypeGUID = $userObjectGUID
                PropertyGUID   = $logonHoursPropertyGUID
            }, 
            @{
                ID             = 124
                Description    = 'Template 124: Specify the computers from which a user can log on'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
                ObjectTypeGUID = $userObjectGUID
                PropertyGUID   = $userWorkstationsPropertyGUID
            }, 
            @{
                ID             = 125
                Description    = 'Template 125: Set Password Never Expires for a user account'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
                ObjectTypeGUID = $userObjectGUID
                PropertyGUID   = $userAccountControlPropertyGUID
            }, 
            @{
                ID             = 126
                Description    = 'Template 126: Set Store Password Using Reversible Encryption for a user account'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
                ObjectTypeGUID = $userObjectGUID
                PropertyGUID   = $userAccountControlPropertyGUID
            }, 
            @{
                ID             = 127
                Description    = 'Template 127: Disable a user account'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
                ObjectTypeGUID = $userObjectGUID
                PropertyGUID   = $userAccountControlPropertyGUID
            }, 
            @{
                ID             = 128
                Description    = 'Template 128: Set Smart card is required for interactive logon for a user account'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
                ObjectTypeGUID = $userObjectGUID
                PropertyGUID   = $userAccountControlPropertyGUID
            }, 
            @{
                ID             = 129
                Description    = 'Template 129: Set Account is sensitive and cannot be delegated for a user account'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
                ObjectTypeGUID = $userObjectGUID
                PropertyGUID   = $userAccountControlPropertyGUID
            }, 
            @{
                ID             = 130
                Description    = 'Template 130: Set Use DES encryption types for this account for a user account'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
                ObjectTypeGUID = $userObjectGUID
                PropertyGUID   = $userAccountControlPropertyGUID
            }, 
            @{
                ID             = 131
                Description    = 'Template 131: Set Do not require Kerberos pre-authentication for a user account'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
                ObjectTypeGUID = $userObjectGUID
                PropertyGUID   = $userAccountControlPropertyGUID
            }, 
            @{
                ID             = 132
                Description    = 'Template 132: Specify the date when a user account expires'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
                ObjectTypeGUID = $userObjectGUID
                PropertyGUID   = $accountExpiresPropertyGUID
            }, 
            @{
                ID             = 133
                Description    = 'Template 133: Specify a profile path for a user'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
                ObjectTypeGUID = $userObjectGUID
                PropertyGUID   = $profilePathPropertyGUID
            }, 
            @{
                ID             = 134
                Description    = 'Template 134: Specify a logon script for a user'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
                ObjectTypeGUID = $userObjectGUID
                PropertyGUID   = $scriptPathPropertyGUID
            },


            #
            # Group Account Templates
            #

            @{
                ID          = 200
                Description = "`n --- Group Account Templates ---"
                #Rights         = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
                #ObjectTypeGUID = $groupObjectGUID
            },
            @{
                ID             = 201
                Description    = 'Template 201: Create, delete and manage groups'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
                ObjectTypeGUID = $groupObjectGUID
            }, 
            @{
                ID             = 202
                Description    = 'Template 202: Modify the membership of a group'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
                ObjectTypeGUID = $groupObjectGUID
                PropertyGUID   = $memberPropertyGUID
            }, 
            @{
                ID             = 203
                Description    = 'Template 203: Create a group'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::CreateChild
                ObjectTypeGUID = $groupObjectGUID
            }, 
            @{
                ID             = 204
                Description    = 'Template 204: Delete a child group'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild
                ObjectTypeGUID = $groupObjectGUID
            }, 
            @{
                ID             = 205
                Description    = 'Template 205: Delete this group'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::Delete
                ObjectTypeGUID = $groupObjectGUID
            }, 
            @{
                ID             = 206
                Description    = 'Template 206: Rename a group'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
                ObjectTypeGUID = $groupObjectGUID
                PropertyGUID   = $cnPropertyGUID
            }, 
            @{
                ID             = 207
                Description    = 'Template 207: Rename a group (Name)'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
                ObjectTypeGUID = $groupObjectGUID
                PropertyGUID   = $namePropertyGUID
            }, 
            @{
                ID             = 208
                Description    = 'Template 208: Specify the Pre-Windows 2000 compatible name for the group'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
                ObjectTypeGUID = $groupObjectGUID
                PropertyGUID   = $sAMAccountNamePropertyGUID
            }, 
            @{
                ID             = 209
                Description    = 'Template 209: Modify the description of a group'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
                ObjectTypeGUID = $groupObjectGUID
                PropertyGUID   = $descriptionPropertyGUID
            }, 
            @{
                ID             = 210
                Description    = 'Template 210: Modify the scope of the group'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
                ObjectTypeGUID = $groupObjectGUID
                PropertyGUID   = $groupTypePropertyGUID
            }, 
            @{
                ID             = 211
                Description    = 'Template 211: Modify the type of the group'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
                ObjectTypeGUID = $groupObjectGUID
                PropertyGUID   = $groupTypePropertyGUID
            }, 
            @{
                ID             = 212
                Description    = 'Template 212: Modify notes for a group'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
                ObjectTypeGUID = $groupObjectGUID
                PropertyGUID   = $infoPropertyGUID
            }, 
            @{
                ID             = 213
                Description    = 'Template 213: Modify group membership'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
                ObjectTypeGUID = $groupObjectGUID
                PropertyGUID   = $memberPropertyGUID
            }, 
            @{
                ID             = 214
                Description    = 'Template 214: Specify Managed-By Information of a Group'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
                ObjectTypeGUID = $groupObjectGUID
                PropertyGUID   = $managedByPropertyGUID
            }, 
    

            #
            # Computer Account Templates
            #

            @{
                ID          = 300
                Description = "`n --- Computer Account Templates ---"
                #Rights         = [System.DirectoryServices.ActiveDirectoryRights]::CreateChild
                #ObjectTypeGUID = $computerObjectGUID
            }, 
            @{
                ID             = 301
                Description    = 'Template 301: Join a computer to the domain'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::CreateChild
                ObjectTypeGUID = $computerObjectGUID
            }, 
            @{
                ID             = 302
                Description    = 'Template 302: Create a computer account'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::CreateChild
                ObjectTypeGUID = $computerObjectGUID
            }, 
            @{
                ID             = 303
                Description    = 'Template 303: Delete a child computer account'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild
                ObjectTypeGUID = $computerObjectGUID
            }, 
            @{
                ID             = 304
                Description    = 'Template 304: Delete this computer account'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::Delete
                ObjectTypeGUID = $computerObjectGUID
            }, 
            @{
                ID             = 305
                Description    = 'Template 305: Rename a computer account'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
                ObjectTypeGUID = $computerObjectGUID
                PropertyGUID   = $cnPropertyGUID
            }, 
            @{
                ID             = 306
                Description    = 'Template 306: Disable a computer account'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
                ObjectTypeGUID = $computerObjectGUID
                PropertyGUID   = $userAccountControlPropertyGUID
            }, 
            @{
                ID           = 307
                Description  = 'Template 307: Reset a computer account'
                Rights       = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
                ControlRight = $resetPasswordGUID
            }, 
            @{
                ID             = 308
                Description    = "Template 308: Specify the computer's description"
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
                ObjectTypeGUID = $computerObjectGUID
                PropertyGUID   = $descriptionPropertyGUID
            }, 
            @{
                ID             = 309
                Description    = 'Template 309: Specify Managed-By information for a computer account'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
                ObjectTypeGUID = $computerObjectGUID
                PropertyGUID   = $managedByPropertyGUID
            }, 
            @{
                ID             = 310
                Description    = 'Template 310: Specify that a computer account be trusted for delegation'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
                ObjectTypeGUID = $computerObjectGUID
                PropertyGUID   = $userAccountControlPropertyGUID
            }, 
    

            #
            # Organizational Unit Templates
            #

            @{
                ID          = 400
                Description = "`n --- Organizational Unit Templates ---"
                #Rights         = [System.DirectoryServices.ActiveDirectoryRights]::CreateChild
                #ObjectTypeGUID = $ouObjectGUID
            }, 
            @{
                ID             = 401
                Description    = 'Template 401: Create an Organizational Unit'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::CreateChild
                ObjectTypeGUID = $ouObjectGUID
            }, 
            @{
                ID             = 402
                Description    = 'Template 402: Delete a child Organizational Unit'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild
                ObjectTypeGUID = $ouObjectGUID
            }, 
            @{
                ID             = 403
                Description    = 'Template 403: Delete this Organizational Unit'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::Delete
                ObjectTypeGUID = $ouObjectGUID
            }, 
            @{
                ID             = 404
                Description    = 'Template 404: Rename an Organizational Unit'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
                ObjectTypeGUID = $ouObjectGUID
                PropertyGUID   = $ouPropertyGUID
            }, 
            @{
                ID             = 405
                Description    = 'Template 405: Rename an Organizational Unit (Name)'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
                ObjectTypeGUID = $ouObjectGUID
                PropertyGUID   = $namePropertyGUID
            }, 
            @{
                ID             = 406
                Description    = 'Template 406: Modify Description of an Organizational Unit'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
                ObjectTypeGUID = $ouObjectGUID
                PropertyGUID   = $descriptionPropertyGUID
            }, 
            @{
                ID             = 407
                Description    = 'Template 407: Modify Managed-By Information of an Organizational Unit'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
                ObjectTypeGUID = $ouObjectGUID
                PropertyGUID   = $managedByPropertyGUID
            }, 
            @{
                ID             = 408
                Description    = 'Template 408: Delegate Control of an Organizational Unit'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl
                ObjectTypeGUID = $ouObjectGUID
            }, 
    

            #
            # inetOrgPerson Templates
            #

            @{
                ID          = 500
                Description = "`n --- inetOrgPerson Templates ---"
                #Rights         = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
                #ObjectTypeGUID = $inetOrgPersonObjectGUID
            },
            @{
                ID             = 501
                Description    = 'Template 501: Create, delete, and manage inetOrgPerson accounts'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
                ObjectTypeGUID = $inetOrgPersonObjectGUID
            }, 
            @{
                ID           = 502
                Description  = 'Template 502: Reset inetOrgPerson passwords and force password change at next logon'
                Rights       = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
                ControlRight = $resetPasswordGUID
            }, 
            @{
                ID             = 503
                Description    = 'Template 503: Read all inetOrgPerson information'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty
                ObjectTypeGUID = $inetOrgPersonObjectGUID
            }, 
    

            #
            # Group Policy Templates
            #

            @{
                ID          = 600
                Description = "`n --- Group Policy Templates ---"
                #Rights         = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
                #ObjectTypeGUID = $gpLinkObjectGUID
            }, 
            @{
                ID             = 601
                Description    = 'Template 601: Manage Group Policy links'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
                ObjectTypeGUID = $gpLinkObjectGUID
            }, 
            @{
                ID             = 602
                Description    = 'Template 602: Manage Group Policy links (Options)'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
                ObjectTypeGUID = $gpOptionsObjectGUID
            }, 
            @{
                ID           = 603
                Description  = 'Template 603: Generate Resultant Set of Policy (Planning)'
                Rights       = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
                ControlRight = $rsopPlanningGUID
            }, 
            @{
                ID           = 604
                Description  = 'Template 604: Generate Resultant Set of Policy (Logging)'
                Rights       = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
                ControlRight = $rsopLoggingGUID
            }, 
    

            #
            # WMI Filter Templates
            #
    
            @{
                ID          = 700
                Description = "`n --- WMI Filter Templates ---"
                #Rights         = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
                #ObjectTypeGUID = $wmiFilterObjectGUID
            }
            @{
                ID             = 701
                Description    = 'Template 701: Create, Delete, and Manage WMI Filters'
                Rights         = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
                ObjectTypeGUID = $wmiFilterObjectGUID
            }
        )
    }
    
    process {

        if ($ShowTemplates) {
            Show-Templates
            continue
        }

        try {
            # Select and apply selectedTemplate
            $selectedTemplate = $templates | Where-Object { $_.ID -eq $TemplateID }

            # Grant Permissions
            Grant-AdPermission -OrganizationalUnitDN $DelegationOuDN -Identity $AdIdentity -Rights $selectedTemplate.Rights `
                -ObjectTypeGUID $selectedTemplate.ObjectTypeGUID -ControlRight $selectedTemplate.ControlRight -PropertyGUID $selectedTemplate.PropertyGUID

            Write-Host -Object '[*] All permissions applied successfully.' -ForegroundColor Green

        }
        catch {
            # Error
            Write-Host -Object "[E] Could not apply permissions! $_" -ForegroundColor Red
        }
    }
    
    end {
        Write-Verbose -Message "[Invoke-ADDelegationTemplate] END"
    }
}
