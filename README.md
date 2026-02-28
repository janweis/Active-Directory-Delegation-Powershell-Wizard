# 🧰 Active Directory Delegation PowerShell Wizard

> **Version:** v1.3-dev &nbsp;|&nbsp; **Last update:** 2026-02 &nbsp;|&nbsp; **Author:** Jan Weis

Automate Active Directory delegation with reusable JSON templates.  
Apply, audit, and revert permissions — consistently, transparently, and in seconds.

---

## ⚡ TL;DR — 3 commands to get started

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
```

---

## 🧾 Requirements

| Requirement | Details |
|---|---|
| PowerShell | Version 3.0 or later |
| Module | `ActiveDirectory` (RSAT or AD DS role) |
| Permissions | Must be able to modify ACLs on the target OU/object |

---

## 📖 Parameters at a glance

| Parameter | Type | Description |
|---|---|---|
| `-Identity` | `string` | AD principal (user/group) receiving the permissions |
| `-Path` | `string` | Target object in distinguishedName format (e.g. an OU) |
| `-TemplateIDs` | `int[]` | One or more template IDs to apply |
| `-TemplatePath` | `string` | Path to a JSON file **or** a directory of JSON files |
| `-ShowTemplates` | `switch` | List all loaded templates |
| `-IncludeDetails` | `switch` | Show rule details and source file per template |
| `-LogChanges` | `switch` | Enable change logging (requires `-LogPath`) |
| `-LogPath` | `string` | Path to the log file |

> **Note:** If `-TemplatePath` is omitted, the script auto-loads from a `templates\` subdirectory next to the script.

---

## 🚀 Usage

### Show available templates

```powershell
# Overview (ID, description, source file)
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

---

## 🔄 Revert changes

Logged changes can be reviewed and reverted at any time:

```powershell
# Show all logged changes
Show-ADDelegationTemplateChanges -LogFilePath "$env:USERPROFILE\DelegationLog.log"

# Show with formatted output
Show-ADDelegationTemplateChanges -LogFilePath "$env:USERPROFILE\DelegationLog.log" -FormatOutput

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

| File | Category | Examples |
|---|---|---|
| `100-user.json` | **User objects** | Reset password, edit properties, manage accounts |
| `200-group.json` | **Group objects** | Manage membership, create/delete groups |
| `300-computer.json` | **Computer objects** | Join domain, reset password |
| `400-organizationalUnit.json` | **Organizational Units** | Create, rename, manage OUs |
| `500-inetOrgPerson.json` | **inetOrgPerson** | LDAP / schema-based environments |
| `600-groupPolicy.json` | **Group Policy** | Link/unlink GPOs, read RSoP |
| `700-wmiFilters.json` | **WMI Filters** | Create, delete, assign WMI filters |

> Use `-ShowTemplates -IncludeDetails` to see the exact template IDs and rules in each file.

---

## 📝 Real-world examples

### Scenario 1 — Helpdesk password reset

The Berlin helpdesk team needs to reset user passwords in a specific OU:

```powershell
.\Invoke-ADDelegationTemplate.ps1 `
  -Identity    "Contoso\Helpdesk-Berlin" `
  -Path        "OU=UsersBerlin,DC=contoso,DC=local" `
  -TemplateIDs 102 `
  -TemplatePath .\templates
```

### Scenario 2 — Full user management with logging

Grant a team full user management rights and log every change:

```powershell
.\Invoke-ADDelegationTemplate.ps1 `
  -Identity    "UserAdmins" `
  -Path        "OU=Users,OU=Corp,DC=contoso,DC=local" `
  -TemplateIDs 101,102,103 `
  -TemplatePath .\templates `
  -LogChanges `
  -LogPath "$env:USERPROFILE\DelegationLog.log"
```

### Scenario 3 — GPO link delegation

Allow a group to link/unlink GPOs on an OU:

```powershell
.\Invoke-ADDelegationTemplate.ps1 `
  -Identity    "GPO-Managers" `
  -Path        "OU=Sites,DC=contoso,DC=local" `
  -TemplateIDs 601 `
  -TemplatePath .\templates
```

---

## 📐 JSON template format

Each JSON file contains an array of templates:

```json
[
  {
    "ID": "101",
    "Description": "User: read & write all properties",
    "AppliesToClasses": "domainDNS,organizationalUnit,container",
    "ObjectTypes": "SCOPE,user",
    "Template": [
      { "ObjectType": "user", "Property": "@",              "Right": "ReadProperty|WriteProperty" },
      { "ObjectType": "user", "Property": "Reset Password", "Right": "ExtendedRight" }
    ]
  }
]
```

| Key | Type | Description |
|---|---|---|
| `ID` | `string` | Unique template identifier |
| `Description` | `string` | Human-readable description |
| `AppliesToClasses` | `string` | Comma-separated AD object classes this template targets |
| `ObjectTypes` | `string` | Comma-separated AD object classes this template applies permissions to |
| `Template` | `array` | Array of permission rules |
| `Template[].ObjectType` | `string` | AD object class (e.g. `user`, `group`, `computer`, `SCOPE`) |
| `Template[].Property` | `string` | Property or extended right name (`@` = all properties) |
| `Template[].Right` | `string` | Full `ActiveDirectoryRights` enum name(s) |

### Merge behavior
- Files are loaded alphabetically.
- Duplicate IDs across files: last-writer-wins (the later file overrides).
- Invalid templates are skipped with a warning — remaining templates still load.

---

## ⚠️ Breaking change in v1.3-dev — Rights format

**Before (v1.2):** Templates used abbreviations like `RP`, `WP`, `CC`, `CONTROLRIGHT`.  
**Now (v1.3-dev):** Templates must use the full `System.DirectoryServices.ActiveDirectoryRights` enum names.

| Old abbreviation | New full name |
|---|---|
| `RP` | `ReadProperty` |
| `WP` | `WriteProperty` |
| `CC` | `CreateChild` |
| `DC` | `DeleteChild` |
| `SD` | `Self` |
| `WD` | `WriteDacl` |
| `CONTROLRIGHT` | `ExtendedRight` |
| `GA` | `GenericAll` |
| `GR` | `GenericRead` |
| `GW` | `GenericWrite` |
| `GE` | `GenericExecute` |
| `LC` | `ListChildren` |

**Multiple rights per rule** are supported — separate with `|` or `,`:
```json
{ "ObjectType": "user", "Property": "@", "Right": "ReadProperty|WriteProperty" }
```

> Validation is case-insensitive. Invalid `Right` values produce a clear warning listing all allowed enum names.

---

## 🔧 Troubleshooting

| Problem | Solution |
|---|---|
| Template is skipped | Check the warning message — it tells you whether `Right`, `ObjectType`, or `Property` is invalid |
| JSON parse error | Validate syntax: `Get-Content .\templates\100-user.json -Raw \| ConvertFrom-Json` |
| "No template with ID X found" | Run `-ShowTemplates` to verify the ID exists and is loaded |
| "Template path not found" | Verify `-TemplatePath` points to an existing file or directory |
| Old abbreviations rejected | Replace abbreviations with full enum names (see migration table above) |

---

## 🔗 Related scripts

| Script | Purpose |
|---|---|
| `Revert-ADDelegationTemplate.ps1` | Revert previously applied permissions using a log file |
| `Show-ADDelegationTemplateChanges.ps1` | Display logged permission changes (formatted or raw) |
| `tools\ConvertFrom-DelegwizToTemplate.ps1` | Convert legacy `delegwiz.ini` files to JSON templates |
| `tools\ConvertFrom-ObjectAclToTemplate.ps1` | Reverse-engineer: generate a template from existing AD permissions |
| `tools\Test-DelegationTemplate.ps1` | Validate a JSON template against the AD schema |

---

## 💬 Community

Suggestions, bug reports, and contributions are welcome!  
Please open an issue or submit a pull request with a clear explanation.

---

## 📚 Source & reference

Template source @Microsoft: [Appendix O: Active Directory Delegation Wizard File](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc772784(v=ws.10))
