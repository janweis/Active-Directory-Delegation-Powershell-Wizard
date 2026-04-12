# Security Reference — AD Attribute Risk Database

> **Schema:** v1.0.0 &nbsp;|&nbsp; **Updated:** 2026-04 &nbsp;|&nbsp; **Entries:** 255

Curated database of AD attributes and extended rights with risk assessments. Used by `Invoke-ADDelegationTemplate.ps1` to generate context-aware security warnings before applying delegations.

---

## How it works

1. **Load** — The script calls `Import-SecurityTemplate` to read `security-reference.json` from this folder.
2. **Match** — For each permission in a template, `Find-SecurityTemplateReference` looks up the `attribute` field. If the reference has `appliesTo` entries, the script picks the context-specific `impact` for the target object type.
3. **Warn** — References at or above `-WarnSeverity` (default `Medium`) trigger a warning showing category, risk level, attack technique, known tools, and reference URL.
4. **Confirm** — A `[Y/N]` prompt blocks before applying. Use `-DisableSecurityWarning` to skip.

---

## JSON schema

```json
{
  "_meta": { "version": "1.0.0", "..." : "..." },
  "references": [
    {
      "id":              "GUID",
      "category":        "Logical grouping",
      "attribute":       "AD attribute or extended right (matching key)",
      "riskLevel":       "Critical | High | Medium | Low",
      "attackTechnique": "Generic attack description",
      "appliesTo":       [{ "object": "user", "impact": "Context-specific description" }],
      "knownTools":      ["Tool1", "Tool2"],
      "referenceURL":    "https://..."
    }
  ]
}
```

| Key | Required | Description |
|---|---|---|
| `id` | yes | GUID — unique identifier |
| `category` | yes | Human-readable grouping (e.g. `Access Control & DACL`, `Kerberos Delegation`) |
| `attribute` | yes | AD attribute or extended right display name — this is the **matching key** against template `Property` values |
| `riskLevel` | yes | `Critical`, `High`, `Medium`, or `Low` |
| `attackTechnique` | yes | Generic attack description (used when no `appliesTo` match) |
| `appliesTo` | no | Array of `{ object, impact }` for context-aware warnings per object type |
| `knownTools` | yes | Array of known offensive tool names |
| `referenceURL` | yes | URL to public attack writeup or schema documentation |

### `appliesTo` — context-aware matching

When present, the script checks `appliesTo[].object` against the target AD object class. If matched, `impact` replaces `attackTechnique` in the warning output.

Known `object` values: `adminSDHolder`, `certificationAuthority`, `computer`, `dnsZone`, `domainDNS`, `group`, `groupPolicyContainer`, `organizationalUnit`, `pKICertificateTemplate`, `user`

16 of 255 references use `appliesTo` — typically for attributes like `nTSecurityDescriptor` or `member` where risk depends heavily on the target object.

---

## Risk levels

| Level | Score | Meaning | Count |
|---|---|---|---|
| `Critical` | 4 | Direct domain/object takeover possible | 66 |
| `High` | 3 | Privilege escalation or persistence possible | 78 |
| `Medium` | 2 | Lateral movement or information disclosure | 74 |
| `Low` | 1 | Low abuse potential | 37 |

The `-WarnSeverity` parameter sets the threshold. Default `Medium` means entries rated `Medium`, `High`, and `Critical` trigger warnings.

---

## Categories (24)

| Category | Count | | Category | Count |
|---|---|---|---|---|
| User Attributes | 55 | | Fine-Grained Password Policies | 9 |
| Additional Attack Vectors | 49 | | Domain & Forest Trust | 7 |
| Extended Rights / Control Plane | 30 | | Exchange / Hybrid Attributes | 7 |
| Other Security-Relevant Attributes | 17 | | Group Policy Objects | 7 |
| Property Sets | 11 | | Schema & Configuration | 6 |
| Computer Objects | 9 | | LAPS | 6 |
| AD Certificate Services | 9 | | Organizational Units | 5 |
| Kerberos Delegation | 5 | | Service Accounts & MSAs | 5 |
| DNS (AD-integrated) | 4 | | GenericAll / WriteDACL / WriteOwner | 4 |
| Group Attributes | 3 | | Rename / Move Attribute | 3 |
| Access Control & DACL | 1 | | AdminSDHolder / Protected Users | 1 |
| inetOrgPerson | 1 | | WMI Filter | 1 |

---

## Warning output example

When a template property matches a reference at or above the severity threshold:

```
WARNING: Property 'nTSecurityDescriptor' has a security warning.
  - Template ID: 100
  - Category: Access Control & DACL
  - Risk Level: Critical
  - Attack Technique: Directly manipulate group DACL - full access
  - Known Tools: Certipy, Custom, PowerView, SharpGPOAbuse
  - Reference: https://attack.mitre.org/techniques/T1222/
```

---

## Adding or editing entries

1. Use a new GUID for each `id` (e.g. `[guid]::NewGuid()` in PowerShell).
2. Set `attribute` to the exact display name the script uses in templates (= `Property` field).
3. Add `appliesTo` only when the risk or impact differs by object type.
4. Validate JSON after editing: `Get-Content .\security\security-reference.json -Raw | ConvertFrom-Json`
