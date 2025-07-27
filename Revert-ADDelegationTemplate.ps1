#requires -Version 3.0

<#
    Author: Jan Weis
    Mail: jan.weis@it-explorations.de
    Version: v1.0
#>

<#
.Synopsis
   Revert the made changes in Active Directory 
.DESCRIPTION
   Revert the changes on an Object in Active Directory
.EXAMPLE
   $changes = Show-ADDelegationTemplateChanges -LogFilePath "$env:USERPROFILE\Documents\DelegationTemplateChanges.txt"
   Revert-ADDelegationTemplate -InputObject $changes
#>

function Revert-ADDelegationTemplate {
    param (
        [Parameter(Mandatory)]
        [PSCustomObject[]]
        $InputObject
    )
    
    begin {
        function Revoke-AdPermission {
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

                [string]$Date = '',
                [string]$Time = '',
                [string]$TemplateID = ''
            )

            $adObject = [ADSI]"LDAP://$ObjectPathDN"

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

            $adObject.ObjectSecurity.RemoveAccessRule($ace)
            $adObject.CommitChanges()
            Write-Verbose -Message ("[*] Revoked permission:`n`tADIdentity = {4} `n`t => Rights = {0}`n`t => Class GUID = {1}`n`t => Property GUID = {2}`n`t OU = {3}" -f $Rights, $ClassGUID, $PropertyGUID, $ObjectPathDN, $Identity)
        }
    }
    
    process {

        Foreach($revertObject in $InputObject) {
            
            $params = @{}
            $revertObject.psobject.properties | ForEach-Object { $params[$_.Name] = $_.Value }
            
            Revoke-AdPermission @params
        }
    }
    
    end {
        
    }
}
