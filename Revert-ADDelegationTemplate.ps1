function Revert-ADDelegationTemplate {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable[]]
        $InputObject
    )
    
    begin {
        function Revoke-AdPermission {
            param (
                [Parameter(Mandatory)]
                [string]$Identity,
            
                [Parameter(Mandatory)]
                [string]$OrganizationalUnitDN,
                
                [Parameter(Mandatory)]
                [System.DirectoryServices.ActiveDirectoryRights]$Rights,
                
                [string]$ObjectTypeGUID = $null,
                [string]$ControlRight = $null,
                [string]$InheritedObjectTypeGUID = $null
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
            elseif ($InheritedObjectTypeGUID) {
                $ace = New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList (
                    [System.Security.Principal.NTAccount]$Identity, 
                    [System.DirectoryServices.ActiveDirectoryRights]$Rights,
                    [System.Security.AccessControl.AccessControlType]::Allow, 
                    [guid]$InheritedObjectTypeGUID,
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

            $adObject.ObjectSecurity.RemoveAccessRule($ace)
            $adObject.CommitChanges()
            Write-Verbose -Message "[*] Revoked permission:`n`tRights = $Rights`n`t => Object Type GUID = $ObjectTypeGUID`n`t => Property GUID = $InheritedObjectTypeGUID`n`t => Control Right = $ControlRight`n`t OU = $OrganizationalUnitDN `n`tADIdentity = $Identity"
        }
    }
    
    process {
        
        $InputObject | ForEach-Object {

            try {
                
                Revoke-AdPermission -Identity $_.Identity -OrganizationalUnitDN $_.OrganizationalUnitDN -Rights $_.Rights -ObjectTypeGUID $_.ObjectTypeGUID `
                    -InheritedObjectTypeGUID $_.InheritedObjectTypeGUID -ControlRight $_.ControlRight
            }
            catch {
                Write-Error -Message "[ERR] Could not undo permissions! $_"
            }
        }
    }
    
    end {
        Write-Verbose -Message "[*] Completed processing all entries."
    }
}