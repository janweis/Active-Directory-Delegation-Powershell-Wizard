# 🛠️ Tools

This directory contains helper scripts and tools for working with Active Directory Delegation Templates.

## 🚀 Quick Start Examples

**1. Convert an old `delegwiz.ini` to the new JSON format:**
```powershell
.\ConvertFrom-DelegwizToTemplate.ps1 -Path .\sample-delegwiz.ini -OutFile ..\templates\converted.json
```

**2. Reverse-engineer existing permissions into a template:**
```powershell
.\ConvertFrom-ObjectAclToTemplate.ps1 -Identity "DOMAIN\Helpdesk" -Path "OU=Users,DC=contoso,DC=local" -TemplateDescription "Helpdesk User Management" -OutputPath .\helpdesk-template.json
```

**3. Validate your custom JSON template:**
```powershell
.\Test-DelegationTemplate.ps1 -Path ..\templates\my-custom-template.json
```

---

## 📦 Available Tools

### `ConvertFrom-DelegwizToTemplate.ps1`
Converts legacy `delegwiz.ini` (Delegation Wizard) templates into the new JSON format used by `Invoke-ADDelegationTemplate`.
- **Usage:** `.\ConvertFrom-DelegwizToTemplate.ps1 -Path .\sample-delegwiz.ini -OutFile ..\templates\converted.json`

### `ConvertFrom-ObjectAclToTemplate.ps1`
Reads the Access Control List (ACL) of an existing Active Directory object for a specific identity and generates a JSON delegation template based on those permissions. This is useful for reverse-engineering existing delegations into reusable templates.
- **Usage:** `.\ConvertFrom-ObjectAclToTemplate.ps1 -Identity "DOMAIN\User" -Path "OU=MyOU,DC=contoso,DC=local" -TemplateDescription "My custom template" -OutputPath .\my-template.json`

### `Test-DelegationTemplate.ps1`
Validates a JSON delegation template against the Active Directory schema. It checks if all specified `ObjectType`, `Property`, and `Right` values are valid and exist in your AD schema.
- **Usage:** `.\Test-DelegationTemplate.ps1 -Path ..\templates\100-user.json`

### `sample-delegwiz.ini`
A sample INI file provided for testing the `ConvertFrom-DelegwizToTemplate.ps1` script.
