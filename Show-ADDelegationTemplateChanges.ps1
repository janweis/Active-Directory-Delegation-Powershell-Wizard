#requires -Version 3.0

<#
    Author: Jan Weis
    Mail: jan.weis@it-explorations.de
    Version: v1.1
#>

<#
.Synopsis
   Show made changes
.DESCRIPTION
   Show made changes on Active Directory Objects logged by Invoke-ADDelegationTemplate
.EXAMPLE
   Show-ADDelegationTemplateChanges -LogFilePath "$env:USERPROFILE\Documents\DelegationTemplateChanges.txt"
#>

function Show-ADDelegationTemplateChanges {
    param (
        [Parameter(Mandatory)]
        [string]$LogFilePath
    )
    
    begin {
    }
    
    process {
        Import-Csv -Path $LogFilePath -Delimiter ';' -Encoding UTF8
    }
    
    end {
    }
}
