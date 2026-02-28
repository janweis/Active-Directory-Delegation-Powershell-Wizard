# Delegation templates (JSON) — Quick start & reference

## 🚀 Quick start

**1. List available templates (with details):**
```powershell
Invoke-ADDelegationTemplate -TemplatePath .\templates -ShowTemplates -IncludeDetails
```

**2. Apply template ID 101 to an OU:**
```powershell
Invoke-ADDelegationTemplate -AdIdentity 'CN=UserManagers,OU=Groups,DC=contoso,DC=local' -AdObjectPathDN 'OU=MyOU,DC=contoso,DC=local' -TemplateIDs 101 -TemplatePath .\templates
```

**3. Apply multiple templates at once:**
```powershell
Invoke-ADDelegationTemplate -AdIdentity 'CN=Helpdesk,OU=Groups,DC=contoso,DC=local' -AdObjectPathDN 'OU=MyOU,DC=contoso,DC=local' -TemplateIDs 101,200,300 -TemplatePath .\templates
```

## 📝 Format
- Top-level: JSON array of template objects.
- Template object keys: ID (string), Description (string), AppliesToClasses (CSV string), ObjectTypes (CSV string), Template (array of rules).
- Rule keys: ObjectType (string), Property (string), Right (string).

## ⚠️ Right values (IMPORTANT — breaking change)
- Use the full System.DirectoryServices.ActiveDirectoryRights enum names (e.g. ReadProperty, WriteProperty, ExtendedRight).
- Abbreviations (e.g. RP, WP, CONTROLRIGHT) are no longer supported.
- Multiple rights per rule are allowed; use `|` or `,` (e.g. "ReadProperty|WriteProperty").
- Validation is case‑insensitive.

## 💡 Minimal example
```json
[
  {
    "ID": "101",
    "AppliesToClasses": "domainDNS,organizationalUnit,container",
    "Description": "Create and manage user accounts",
    "ObjectTypes": "SCOPE,user",
    "Template": [
      { "ObjectType": "SCOPE", "Property": "user", "Right": "CreateChild" },
      { "ObjectType": "user", "Property": "@", "Right": "ReadProperty|WriteProperty" },
      { "ObjectType": "user", "Property": "Reset Password", "Right": "ExtendedRight" }
    ]
  }
]
```

## ⚙️ Behavior & rules
- Provide either a single JSON file or a directory of JSON files.
- Files are read alphabetically; on duplicate IDs the later file wins (last‑writer‑wins).
- Invalid templates are skipped and a warning is emitted.
- `-TemplatePath` is required — the cmdlet contains no built‑in templates.

## 🔄 Migration hints (short mapping)
- RP  → ReadProperty
- WP  → WriteProperty
- CC  → CreateChild
- DC  → DeleteChild
- SD  → Self
- WD  → WriteDacl
- CONTROLRIGHT → ExtendedRight
- GA/GE/GR/GW → GenericAll / GenericExecute / GenericRead / GenericWrite

## 🔧 Troubleshooting
- **JSON syntax check:** 
  ```powershell
  Get-Content .\templates\100-user.json -Raw | ConvertFrom-Json
  ```
- **Show templates with source file:** 
  ```powershell
  Invoke-ADDelegationTemplate -TemplatePath .\templates -ShowTemplates -IncludeDetails
  ```
- Invalid `Right` values will be rejected with a clear warning listing allowed enum names.

## 📌 Notes
- This README matches v1.3‑dev behaviour: templates must use full enum names and may specify multiple rights per rule.
- Update your external JSON templates before upgrading to v1.3 if they still use abbreviations.

