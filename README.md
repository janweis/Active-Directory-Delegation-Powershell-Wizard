# 🧰 Active Directory Delegation PowerShell Wizard
Last Update: 2025-07
Current Version: v1.1

A PowerShell script to automate delegation of permissions in Active Directory — based on predefined templates.

## 🔍 Purpose

This script helps administrators assign permissions in Active Directory in a consistent, transparent, and repeatable way.

Delegation is applied based on predefined templates for various object types such as users, groups, computers, organizational units, Group Policy Objects (GPOs), and more.

---

## 🧾 Requirements

- PowerShell version 3.0 or higher
- ActiveDirectory PowerShell module (e.g., via RSAT or AD DS role)

---

## 🚀 Usage

### 1. Show available templates

Run this command to display a list of available delegation templates:

```powershell
Invoke-ADDelegationTemplate -ShowTemplates
```
```powershell
Invoke-ADDelegationTemplate -ShowTemplatesDetailed
```
```Powershell
Invoke-ADDelegationTemplate -ShowUserTemplates -ShowGroupTemplates
```

### 2. Apply a template

Use this command to assign a delegation template to a specific organizational unit:

```powershell
Invoke-ADDelegationTemplate `
  -AdIdentity "Helpdesk-Team" `
  -AdObjectPathDN "OU=UsersBerlin,DC=contoso,DC=local" `
  -TemplateID 102
```
Apply multiple templates
```powershell
Invoke-ADDelegationTemplate `
  -AdIdentity "Helpdesk-Team" `
  -AdObjectPathDN "OU=UsersBerlin,DC=contoso,DC=local" `
  -TemplateID 102,103
```
---

## 📦 Included Templates

The script currently includes built-in templates for the following scenarios:

- **User objects**  
  e.g., password reset, edit properties

- **Group objects**  
  e.g., manage membership, create/delete groups

- **Computer objects**  
  e.g., join domain, reset password

- **Organizational Units (OUs)**  
  e.g., manage, create, rename

- **inetOrgPerson**  
  Useful for LDAP or schema-based environments

- **Group Policy Objects (GPOs)**  
  e.g., link/unlink GPOs, read RSoP

- **WMI Filters**  
  Create, delete, assign filters
---

## 📝 Example: Helpdesk Password Reset Permissions
A helpdesk team should be able to reset user passwords in a specific OU:
```Powershell
Invoke-ADDelegationTemplate `
  -AdIdentity "Contoso\Helpdesk-Berlin" `
  -AdObjectPathDN "OU=UsersBerlin,DC=contoso,DC=local" `
  -TemplateID 102
```

**Set** permission(s) to an Organizational Unit (OU)
```Powershell
Invoke-ADDelegationTemplate -AdIdentity "ThisIsMyAdGroup" -AdObjectPathDN "OU=Users,OU=MyStartOU,DC=MyDomain,DC=de" `
  -TemplateID 111
```

**Set** permission(s) to an Organizational Unit (OU) AND **Log** changes
```Powershell
Invoke-ADDelegationTemplate -AdIdentity "ThisIsMyAdGroup" -AdObjectPathDN "OU=Users,OU=MyStartOU,DC=MyDomain,DC=de" `
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
---

## Community

Suggestions, bug reports, and contributions are welcome!
Please open an issue or submit a pull request with a clear explanation of your changes or ideas.

---

## Source

Template source @Microsoft: [Appendix O: Active Directory Delegation Wizard File](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc772784(v=ws.10)?redirectedfrom=MSDN)
