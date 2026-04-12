# 🔐 Active Directory Delegation PowerShell Wizard

> **Version:** v1.4-prod &nbsp;|&nbsp; **Last update:** 2026-04 &nbsp;|&nbsp; **Author:** Jan Weis

Automate Active Directory delegation with reusable JSON templates.  
Apply, audit, and revert permissions — consistently, transparently, and in seconds.  
Context-aware security warnings protect against high-risk delegations.

---

## ⚡ TL;DR — 4 commands to get started

```powershell
# 1. List all available templates
.\Invoke-ADDelegationTemplate.ps1 -ShowTemplates -TemplatePath .\templates

# 2. Apply template 101 to an OU
.\Invoke-ADDelegationTemplate.ps1 `
  -Identity    "Contoso\Helpdesk-Berlin" `
  -Path        "OU=UsersBerlin,DC=contoso,DC=local" `
  -TemplateIDs 101 `
  -TemplatePath .\templates

# 3. Apply with change logging (for easy rollback)
.\Invoke-ADDelegationTemplate.ps1 `
  -Identity    "Contoso\Helpdesk-Berlin" `
  -Path        "OU=UsersBerlin,DC=contoso,DC=local" `
  -TemplateIDs 101,102 `
  -TemplatePath .\templates `
  -LogChanges `
  -LogPath "$env:USERPROFILE\DelegationLog.log"

# 4. Adjust security warning threshold
.\Invoke-ADDelegationTemplate.ps1 `
  -Identity    "Contoso\Helpdesk-Berlin" `
  -Path        "OU=UsersBerlin,DC=contoso,DC=local" `
  -TemplateIDs 100 `
  -TemplatePath .\templates `
  -WarnSeverity Critical
```

> 🛡️ **New in v1.4** — Every delegation is checked against a curated risk database.  
> High-risk permissions trigger an interactive warning before they are applied.

## 📖 Parameters at a glance

| Parameter | Type | Description |
|---|---|---|
| `-Identity` | `string` | AD principal (user/group) receiving the permissions |
| `-Path` | `string` | Target object in distinguishedName format (e.g. an OU) |
| `-TemplateIDs` | `int[]` | One or more template IDs to apply |
| `-TemplatePath` | `string` | Path to a JSON file **or** a directory of JSON files |
| `-ShowTemplates` | `switch` | List all loaded templates (grouped by Object Type → Category) |
| `-IncludeDetails` | `switch` | Show rule details and source file per template |
| `-LogChanges` | `switch` | Enable change logging (requires `-LogPath`) |
| `-LogPath` | `string` | Path to the log file |
| `-WarnSeverity` | `string` | Minimum risk level for security warnings: `Critical`, `High`, `Medium` (default), `Low` |
| `-DisableSecurityWarning` | `switch` | Suppress all security warnings and the interactive confirmation prompt |

> **Note:** If `-TemplatePath` is omitted, the script auto-loads from a `templates\` subdirectory next to the script.

---

## 🚀 Usage

### Show available templates

```powershell
# Overview — grouped by Object Type and Category
.\Invoke-ADDelegationTemplate.ps1 -ShowTemplates -TemplatePath .\templates

# Detailed view (includes rules & AppliesTo info)
.\Invoke-ADDelegationTemplate.ps1 -ShowTemplates -IncludeDetails -TemplatePath .\templates
```

### Apply one or more templates

```powershell
# Single template
.\Invoke-ADDelegationTemplate.ps1 `
  -Identity    "Helpdesk-Team" `
  -Path        "OU=UsersBerlin,DC=contoso,DC=local" `
  -TemplateIDs 102 `
  -TemplatePath .\templates

# Multiple templates at once
.\Invoke-ADDelegationTemplate.ps1 `
  -Identity    "Helpdesk-Team" `
  -Path        "OU=UsersBerlin,DC=contoso,DC=local" `
  -TemplateIDs 101,102,103 `
  -TemplatePath .\templates
```

### Apply with change logging

```powershell
.\Invoke-ADDelegationTemplate.ps1 `
  -Identity    "Helpdesk-Team" `
  -Path        "OU=UsersBerlin,DC=contoso,DC=local" `
  -TemplateIDs 102 `
  -TemplatePath .\templates `
  -LogChanges `
  -LogPath "$env:USERPROFILE\DelegationLog.log"
```

### Control security warnings

```powershell
# Only warn on Critical-risk delegations
.\Invoke-ADDelegationTemplate.ps1 `
  -Identity    "Helpdesk-Team" `
  -Path        "OU=UsersBerlin,DC=contoso,DC=local" `
  -TemplateIDs 100 `
  -TemplatePath .\templates `
  -WarnSeverity Critical

# Suppress warnings entirely (non-interactive / CI use)
.\Invoke-ADDelegationTemplate.ps1 `
  -Identity    "Helpdesk-Team" `
  -Path        "OU=UsersBerlin,DC=contoso,DC=local" `
  -TemplateIDs 100 `
  -TemplatePath .\templates `
  -DisableSecurityWarning
```

---

## 🛡️ Security reference system

`security\security-reference.json` contains a curated risk database for AD attributes and extended rights. When applying a template, the script matches each permission against this database (context-aware per object type) and displays warnings for entries that meet or exceed `-WarnSeverity` (default `Medium`). A `[Y/N]` prompt blocks until confirmed — use `-DisableSecurityWarning` to skip.

### Risk levels

| Level | Meaning |
|---|---|
| `Critical` | Direct domain or object takeover possible |
| `High` | Privilege escalation or persistence possible |
| `Medium` | Lateral movement or information disclosure |
| `Low` | Low abuse potential |

---

## 🔄 Revert changes

Logged changes can be reviewed and reverted at any time:

```powershell
# Show all logged changes
Show-ADDelegationTemplateChanges -LogFilePath "$env:USERPROFILE\DelegationLog.log"

# Revert all logged changes
Show-ADDelegationTemplateChanges -LogFilePath "$env:USERPROFILE\DelegationLog.log" | `
  Revert-ADDelegationTemplate

# Revert only a specific template
Show-ADDelegationTemplateChanges -LogFilePath "$env:USERPROFILE\DelegationLog.log" | `
  Where-Object { $_.TemplateID -eq "102" } | `
  Revert-ADDelegationTemplate
```

---

## 📦 Included template categories

Templates are shipped as JSON files in the `templates\` folder:

| File | Object Type | Examples |
|---|---|---|
| `100-user.json` | **User objects** | Reset password, edit properties, manage accounts |
| `200-group.json` | **Group objects** | Manage membership, create/delete groups |
| `300-computer.json` | **Computer objects** | Join domain, reset password |
| `400-organizationalUnit.json` | **Organizational Units** | Create, rename, manage OUs |
| `500-groupPolicy.json` | **Group Policy** | Link/unlink GPOs, read RSoP |
| `600-wmi.json` | **WMI Filters** | Create, delete, assign WMI filters |
| `700-inetOrgPerson.json` | **inetOrgPerson** | LDAP / schema-based environments |

> Use `-ShowTemplates -IncludeDetails` to see the exact template IDs and rules in each file.  
> JSON format, schema reference, and Rights migration guide → [`templates/README.md`](templates/README.md)

---

## ⚠️ Breaking changes

### v1.4-prod — Least-privilege & security warnings

- **`GenericAll` removed from default templates.** Templates like `100`, `200`, `300`, `600`, `700` now use granular rights (`ReadProperty|WriteProperty`, `CreateChild|DeleteChild`, etc.) instead of `GenericAll`. If you depend on `GenericAll`, create a custom template.
- **Template ID renumbering.** Several IDs changed across template files (e.g. user templates expanded to `100`–`152`, group to `200`–`214`, computer to `300`–`312`). Compare with the CHANGELOG or run `-ShowTemplates` to verify your IDs.
- **Interactive security confirmation.** When a template touches high-risk properties (as defined in `security-reference.json`), the script displays a warning and prompts `[Y/N]` before applying. For non-interactive or CI use, pass `-DisableSecurityWarning`.
- **`Category` field required.** Templates now include a `Category` field used for grouped display in `-ShowTemplates`.

> v1.3 Rights enum migration (abbreviations → full names): see [`templates/README.md`](templates/README.md#v13--rights-enum-migration)

---

##  Community

Suggestions, bug reports, and contributions are welcome!  
Please open an issue or submit a pull request with a clear explanation.

---

## 📚 Source & reference

Template source @Microsoft: [Appendix O: Active Directory Delegation Wizard File](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc772784(v=ws.10))
