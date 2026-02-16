Delegation templates (JSON) — Quick start & reference

Quick start
- List available templates (with details):
  Invoke-ADDelegationTemplate -TemplatePath .\templates -ShowTemplates -IncludeDetails
- Apply template ID 101 to an OU:
  Invoke-ADDelegationTemplate -AdIdentity 'CN=UserManagers,OU=Groups,DC=contoso,DC=local' -AdObjectPathDN 'OU=MyOU,DC=contoso,DC=local' -TemplateIDs 101 -TemplatePath .\templates

Format
- Top-level: JSON array of template objects.
- Template object keys: ID (int), Description (string), AppliesTo (CSV string), Template (array of rules).
- Rule keys: Class (string), Property (string), Right (string).

Right values (IMPORTANT — breaking change)
- Use the full System.DirectoryServices.ActiveDirectoryRights enum names (e.g. ReadProperty, WriteProperty, ExtendedRight).
- Abbreviations (e.g. RP, WP, CONTROLRIGHT) are no longer supported.
- Multiple rights per rule are allowed; use `|` or `,` (e.g. "ReadProperty|WriteProperty").
- Validation is case‑insensitive.

Minimal example
```
[
  {
    "ID": 101,
    "Description": "Create and manage user accounts",
    "AppliesTo": "domainDNS,organizationalUnit,container",
    "Template": [
      { "Class": "user", "Property": "@", "Right": "ReadProperty|WriteProperty" },
      { "Class": "user", "Property": "Reset Password", "Right": "ExtendedRight" }
    ]
  }
]
```

Behavior & rules
- Provide either a single JSON file or a directory of JSON files.
- Files are read alphabetically; on duplicate IDs the later file wins (last‑writer‑wins).
- Invalid templates are skipped and a warning is emitted.
- `-TemplatePath` is required — the cmdlet contains no built‑in templates.

Migration hints (short mapping)
- RP  → ReadProperty
- WP  → WriteProperty
- CC  → CreateChild
- DC  → DeleteChild
- SD  → Self
- WD  → WriteDacl
- CONTROLRIGHT → ExtendedRight
- GA/GE/GR/GW → GenericAll / GenericExecute / GenericRead / GenericWrite

Troubleshooting
- JSON syntax check: `Get-Content .\templates\100-user.json -Raw | ConvertFrom-Json`
- Show templates with source file: `Invoke-ADDelegationTemplate -TemplatePath .\templates -ShowTemplates -IncludeDetails`
- Invalid `Right` values will be rejected with a clear warning listing allowed enum names.

Notes
- This README matches v1.3‑dev behaviour: templates must use full enum names and may specify multiple rights per rule.
- Update your external JSON templates before upgrading to v1.3 if they still use abbreviations.

