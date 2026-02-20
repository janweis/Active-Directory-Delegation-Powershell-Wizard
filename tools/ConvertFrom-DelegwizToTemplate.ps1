<#
.SYNOPSIS
  Konvertiert Delegwiz/INI-Templates in die JSON/PSObject-Struktur.

.PARAMETER Path
  Pfad zur INI-/Delegwiz-Datei (optional).

.PARAMETER Content
  INI-Inhalt als String (optional).

.PARAMETER OutFile
  Ziel-Datei (JSON). Wenn nicht gesetzt, wird das PSObject zurückgegeben.

.PARAMETER PadDigits
  Anzahl Ziffern für ID-Padding (Default: 3).

.EXAMPLE
  Convert-DelegwizToTemplate -Path .\delegwiz.ini -OutFile .\templates\converted.json

  $templates = Convert-DelegwizToTemplate -Content $data
#>

param(
    [string]$Path,
    [string]$Content,
    [string]$OutFile,
    [int]$PadDigits = 3
)

function Convert-DelegwizToTemplate {
    param(
        [string]$RawContent,
        [int]$Pad = 3
    )

    if (-not $RawContent) { throw 'Kein Inhalt übergeben.' }

    # Mapping kurz -> Right (erweiterbar)
    $map = @{
        'CC' = 'CreateChild'; 'DC' = 'DeleteChild'; 'GA' = 'GenericAll'
        'RP' = 'ReadProperty'; 'WP' = 'WriteProperty'
        'SD' = 'Delete'; 'WD' = 'WriteDacl'
    }

    # --- Abschnitts‑Parsing (robust) ---
    $sectionPattern = '(?ms)^\s*\[(?<name>[^\]]+)\]\s*(?<body>.*?)(?=^\s*\[|\z)'
    $regexOptions = [System.Text.RegularExpressions.RegexOptions]::Multiline -bor [System.Text.RegularExpressions.RegexOptions]::Singleline
    $matches = [regex]::Matches($RawContent, $sectionPattern, $regexOptions)

    $sections = [ordered]@{}
    foreach ($m in $matches) {
        $name = $m.Groups['name'].Value.Trim()
        $body = $m.Groups['body'].Value -split "`r?`n" |
                ForEach-Object { $_.Trim() } |
                Where-Object { $_ -and -not ($_ -match '^\s*;') }
        $sections[$name] = $body
    }

    # Sammle Basen (nur exakte 'templateN') in aufsteigender Reihenfolge — vermeidet Duplikate aus sub‑Sektionen
    $bases = $sections.Keys |
             Where-Object { $_ -match '^template\d+$' } |
             ForEach-Object {
                 if ($_ -match '^template(\d+)$') { [PSCustomObject]@{ Base = $_; Num = [int]$matches[1] } }
             } |
             Sort-Object Num

    $result = @()

    foreach ($b in $bases) {
        # base name ist z.B. 'template1'
        $baseName = $b.Base
        $num = $b.Num
        $id = $num.ToString("D$Pad")

        # defaults
        $applies = ''
        $desc = ''
        $objectTypes = ''
        $templateItems = @()

        # --- Base keys (AppliesToClasses / Description / ObjectTypes) ---
        if ($sections.Contains($baseName)) {
            foreach ($line in $sections[$baseName]) {
                $parts = $line -split '=', 2
                if ($parts.Count -lt 2) { continue }
                $k = $parts[0].Trim()
                $v = $parts[1].Trim().Trim('"').Trim()

                switch ($k.ToLower()) {
                    'appliestoclasses' { $applies = (($v -split ',') | ForEach-Object { $_.Trim() }) -join ',' }
                    'description'      { $desc = $v }
                    'objecttypes'      { $objectTypes = (($v -split ',') | ForEach-Object { $_.Trim() }) -join ',' }
                }
            }
        }

        # --- Subsektionen (templateN.<ObjectType>) ---
        $subSections = $sections.Keys | Where-Object { $_ -like "$baseName.*" }
        foreach ($sub in $subSections) {
            $objectType = ($sub -split '\.',2)[1]
            foreach ($line in $sections[$sub]) {
                $parts = $line -split '=', 2
                if ($parts.Count -lt 2) { continue }
                $prop = $parts[0].Trim()
                $val = $parts[1].Trim().Trim('"').Trim()

                if ($prop -ieq 'CONTROLRIGHT') {
                    # Entire string is an extended right
                    $templateItems += [PSCustomObject]@{ ObjectType = $objectType; Property = $val; Right = 'ExtendedRight' }
                    continue
                }

                # Value can be multiple short codes separated by comma (CC,DC,RP,WP,...)
                $tokens = $val -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
                foreach ($t in $tokens) {
                    $code = $t.ToUpper()
                    if ($map.ContainsKey($code)) {
                        $templateItems += [PSCustomObject]@{ ObjectType = $objectType; Property = $prop; Right = $map[$code] }
                    }
                    else {
                        Write-Warning "Unbekannter Token '$t' in Sektion '$sub' (Property '$prop') — übersprungen."
                    }
                }
            }
        }

        $result += [PSCustomObject]@{
            ID = $id
            AppliesToClasses = $applies
            Description = $desc
            ObjectTypes = $objectTypes
            Template = $templateItems
        }
    }

    return $result
}

# --- entrypoint ---
if (-not $Content -and $Path) {
    $Content = Get-Content -Raw -Encoding UTF8 -Path $Path
}

$converted = Convert-DelegwizToTemplate -RawContent $Content -Pad $PadDigits

if ($OutFile) {
    $converted | ConvertTo-Json -Depth 6 | Set-Content -Path $OutFile -Encoding UTF8
    Write-Output "Wrote JSON to: $OutFile"
} else {
    return $converted
}