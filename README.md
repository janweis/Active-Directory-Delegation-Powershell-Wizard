# Active Directory Delegation Powershell-Wizard
This PowerShell script is used to assign permissions in Active Directory based on predefined templates.  It enables administrators to configure specific rights and properties for user, group, computer and OU objects in Active Directory.

## Features
* Log and Revert changes made
* Easy to extend

## Show Templates (Examples)

**Show** all templates
```Powershell
Invoke-ADDelegationTemplate -ShowTemplates
```

**Show** specific categorie templates
```Powershell
Invoke-ADDelegationTemplate -ShowUserTemplates -ShowGroupTemplates
```

## Use Templates (Examples)

**Set** permission(s) to an Organizational Unit (OU)
```Powershell
Invoke-ADDelegationTemplate -AdIdentity "ThisIsMyAdGroup" -DelegationOuDN "OU=Users,OU=MyStartOU,DC=MyDomain,DC=de" `
  -TemplateID 111
```

**Set** permission(s) to an Organizational Unit (OU) AND **Log** changes
```Powershell
Invoke-ADDelegationTemplate -AdIdentity "ThisIsMyAdGroup" -DelegationOuDN "OU=Users,OU=MyStartOU,DC=MyDomain,DC=de" `
  -TemplateID 111 -LogChanges -LogPath "$env:USERPROFILE\AdOuPermissionChanges.log"
```

## Revert Templates (Examples)

**Show** logged changes
```Powershell
Show-ADDelegationTemplateChanges -LogFilePath "$env:USERPROFILE\AdOuPermissionChanges.log"
```

**Show** logged changes with format
```Powershell
Show-ADDelegationTemplateChanges -LogFilePath "$env:USERPROFILE\AdOuPermissionChanges.log" -FormatOutput
```

**Revert** all changes
```Powershell
Show-ADDelegationTemplateChanges -LogFilePath "$env:USERPROFILE\AdOuPermissionChanges.log" | Revert-ADDelegationTemplate
```

**Revert** specific template changes
```Powershell
$templateChanges = Show-ADDelegationTemplateChanges -LogFilePath "$env:USERPROFILE\AdOuPermissionChanges.log" | Where-Object {$_.TemplateID -eq "111"}
Revert-ADDelegationTemplate -InputObject $templateChanges
```

## Community
Everyone is welcome to participate.

## Source

Template source @Microsoft: [Appendix O: Active Directory Delegation Wizard File](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc772784(v=ws.10)?redirectedfrom=MSDN)
