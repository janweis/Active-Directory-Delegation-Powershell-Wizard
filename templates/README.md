# Delegation Templates — JSON Format & Reference

> **Matches:** v1.4-prod &nbsp;|&nbsp; **Updated:** 2026-04

---

## JSON schema

Each file is a JSON array of template objects:

```json
[
  {
    "ID": "100",
    "Category": "Account Lifecycle",
    "AppliesToClasses": "domainDNS,organizationalUnit,container",
    "Description": "Create, delete, and manage user accounts",
    "ObjectTypes": "SCOPE,user",
    "Template": [
      { "ObjectType": "SCOPE", "Property": "user", "Right": "CreateChild" },
      { "ObjectType": "SCOPE", "Property": "user", "Right": "DeleteChild" },
      { "ObjectType": "user",  "Property": "@",    "Right": "ReadProperty" },
      { "ObjectType": "user",  "Property": "@",    "Right": "WriteProperty" }
    ]
  },
  {
    "ID": "101",
    "Category": "Account Lifecycle",
    "ObjectClass": "User",
    "AppliesToClasses": "domainDNS,organizationalUnit,container",
    "Description": "Create a user account in disabled state",
    "ObjectTypes": "SCOPE",
    "Template": [
      { "ObjectType": "SCOPE", "Property": "user", "Right": "CreateChild" }
    ]
  }
]
```

| Key | Type | Required | Description |
|---|---|---|---|
| `ID` | `string` | yes | Unique numeric identifier (e.g. `"100"`) |
| `Category` | `string` | yes | Grouping for `-ShowTemplates` output (see [Categories per file](#categories-per-file)) |
| `ObjectClass` | `string` | no | Display name for `-ShowTemplates` grouping (e.g. `User`, `Group`, `Computer`). If omitted, derived from `ObjectTypes`. |
| `AppliesToClasses` | `string` | yes | Comma-separated AD classes this template targets (e.g. `domainDNS,organizationalUnit,container`) |
| `Description` | `string` | yes | Human-readable label |
| `ObjectTypes` | `string` | yes | Comma-separated AD classes for ACE inheritance; `SCOPE` = container-level rule |
| `Template[]` | `array` | yes | Permission rules — **one right per rule** (see below) |

### Rule keys (`Template[]`)

| Key | Type | Description |
|---|---|---|
| `ObjectType` | `string` | AD object class (e.g. `user`, `group`, `computer`) or `SCOPE` for container-level |
| `Property` | `string` | AD attribute, extended right, or `@` (= all properties) |
| `Right` | `string` | **Single** `ActiveDirectoryRights` enum name (e.g. `ReadProperty`, `WriteProperty`) |

> **Convention:** Each right gets its own rule entry. Use separate rules instead of combining rights with `|`.

---

## Allowed Right values

Use the full `System.DirectoryServices.ActiveDirectoryRights` enum names. Validation is case-insensitive.

| Enum name | Typical use |
|---|---|
| `ReadProperty` | Read a specific attribute |
| `WriteProperty` | Write a specific attribute |
| `CreateChild` | Create child objects of a type |
| `DeleteChild` | Delete child objects of a type |
| `Delete` | Delete the object itself |
| `Self` | Validated writes (e.g. add/remove self from group) |
| `WriteDacl` | Modify the object's ACL |
| `ExtendedRight` | Extended rights (Reset Password, Change Password, …) |
| `GenericAll` | Full control — **avoid in production** |
| `GenericRead` | Read all properties + list |
| `GenericWrite` | Write all properties |
| `GenericExecute` | Read permissions + list children |
| `ListChildren` | List child objects |

The script also accepts `|` or `,` separated rights (e.g. `"ReadProperty|WriteProperty"`), but the shipped templates use **one right per rule** for clarity.

---

## Merge & load behavior

- Provide a single `.json` file or a directory via `-TemplatePath`.
- Files are loaded **alphabetically** — on duplicate IDs the later file wins (last-writer-wins).
- Invalid templates are skipped with a warning; remaining templates still load.
- If `-TemplatePath` is omitted, the script auto-loads from `templates\` next to the script.

---

## Categories per file

| File | Templates | Categories |
|---|---|---|
| `100-user.json` | 53 | Account Lifecycle, Account, General, Password, Security |
| `200-group.json` | 15 | Account Lifecycle, General, Membership |
| `300-computer.json` | 13 | Account Lifecycle, General, Security |
| `400-organizationalUnit.json` | 7 | Account Lifecycle, General, Security |
| `500-groupPolicy.json` | 3 | Group Policy |
| `600-wmi.json` | 1 | Account Lifecycle |
| `700-inetOrgPerson.json` | 3 | Account Lifecycle, General, Password |

---

## Breaking changes (template-specific)

### v1.4 — Least-privilege & Category

- **`GenericAll` replaced.** Templates `100`, `200`, `300`, `600`, `700` now use granular rights instead of `GenericAll`.
- **`Category` field required.** Every template must include a `Category` string.
- **ID renumbering.** User: `100`–`152` (53 templates), Group: `200`–`214` (15), Computer: `300`–`312` (13). Run `-ShowTemplates` to verify.

### v1.3 — Rights enum migration

Templates must use full enum names. Old abbreviations no longer work:

| Old | New | | Old | New |
|---|---|---|---|---|
| `RP` | `ReadProperty` | | `WD` | `WriteDacl` |
| `WP` | `WriteProperty` | | `CONTROLRIGHT` | `ExtendedRight` |
| `CC` | `CreateChild` | | `GA` | `GenericAll` |
| `DC` | `DeleteChild` | | `GR` | `GenericRead` |
| `SD` | `Self` | | `GW` | `GenericWrite` |
| `LC` | `ListChildren` | | `GE` | `GenericExecute` |

---

## Troubleshooting

```powershell
# Validate JSON syntax
Get-Content .\templates\100-user.json -Raw | ConvertFrom-Json

# List all templates with details and source file
.\Invoke-ADDelegationTemplate.ps1 -ShowTemplates -IncludeDetails -TemplatePath .\templates
```

- Invalid `Right` values are rejected with a warning listing all allowed enum names.
- Missing `Category` results in ungrouped display in `-ShowTemplates`.

