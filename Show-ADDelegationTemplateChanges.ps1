


function Show-ADDelegationTemplateChanges {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$LogFilePath
    )
    
    begin {
        function Read-PermissionChangesFromLog {
            [CmdletBinding()]
            param (
                [Parameter(Mandatory)]
                [string]$LogFilePath
            )
        
            # Read Logfile
            $delegChanges = Get-Content -Path $LogFilePath -Encoding utf8
        
            if ($null -eq $delegChanges) {
                # Log is empty, Exit!
                return
            }
            
            $logList = foreach ($change in $delegChanges) {
        
                # Datum, Uhrzeit, OU, Identity, Permisson, ObjectType, Property, ControlRight
                $changeArray = $change -split ";"
                @{
                    Date                 = $changeArray[0]
                    Time                 = $changeArray[1]
                    TemplateID           = $changeArray[2]
                    OrganizationalUnitDN = $changeArray[3]
                    Identity             = $changeArray[4]
                    Rights               = $changeArray[5]
                    ObjectTypeGUID       = $changeArray[6]
                    PropertyGUID         = $changeArray[7]
                    ControlRight         = $changeArray[8]
                }
            }
        
            return $logList
        }
    
        Write-Verbose -Message "Reading delegation template changes from log file: $LogFilePath"
    }
    
    process {
        
        # Get Log entries
        $entries = Read-PermissionChangesFromLog -LogFilePath $LogFilePath

        # Formatted Output
        Format-Table -InputObject $entries -AutoSize -Property @{label = "Date"; Expression = { $_.Date } }, @{label = "Time"; Expression = { $_.Time } }, `
        @{label = "TemplateID"; Expression = { $_.TemplateID } }, @{label = "OrganizationalUnit"; Expression = { $_.OrganizationalUnitDN } }, `
        @{label = "Identity"; Expression = { $_.Identity } }, @{label = "Rights"; Expression = { $_.Rights } }, @{label = "ObjectTypeGUID"; Expression = { $_.ObjectTypeGUID } }, `
        @{label = "PropertyGUID"; Expression = { $_.PropertyGUID } }, @{label = "ControlRight"; Expression = { $_.ControlRight } }
    }
    
    end {
        Write-Verbose -Message "Finished processing log file: $LogFilePath"
    }
}