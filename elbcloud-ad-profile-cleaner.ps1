<#
.SYNOPSIS
  Profile Cleanup – Stufe 1 (AD-only)

.DESCRIPTION
  Löscht lokale Benutzerprofile nur dann, wenn
  - das Gerät AD-joined ist
  - ein Domain Controller sicher erreichbar ist
  - das Profil einer Domain-SID gehört
  - das Profil nicht geladen ist
  - der AD-Benutzer deaktiviert oder nicht mehr vorhanden ist

  KEINE Zeitlogik, KEIN LastUseTime, KEIN NTUSER.DAT, KEINE Heuristiken.

.NOTES
  Muss als SYSTEM oder Administrator laufen.
#>

[CmdletBinding()]
param(
    [string]$LogPath = "C:\ProgramData\elbcloud\ProfileCleanup.log",
    [switch]$WhatIf
)

# ---------------- Logging ----------------
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logDir    = Split-Path -Path $LogPath -Parent
$logName   = [System.IO.Path]::GetFileNameWithoutExtension($LogPath)
$logExt    = [System.IO.Path]::GetExtension($LogPath)
$LogPath   = Join-Path -Path $logDir -ChildPath ("{0}_{1}{2}" -f $logName, $timestamp, $logExt)

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts] [$Level] $Message"
    Write-Host $line
    try { Add-Content -Path $LogPath -Value $line -ErrorAction Stop } catch {}
}

if (-not (Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}

Write-Log "=== Profil-Bereinigung gestartet (Stufe 1 / AD-only) ==="
Write-Log "WhatIf: $WhatIf"

# ---------------- OS & Domain Check ----------------
try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    if ($os.ProductType -ne 1) {
        Write-Log "Server-OS erkannt – Skript wird nicht ausgeführt." "WARN"
        exit 0
    }

    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    if (-not $cs.PartOfDomain) {
        Write-Log "Computer ist nicht domain-joined – Abbruch." "WARN"
        exit 0
    }

    $domainName = $cs.Domain
    Write-Log "Computer ist domain-joined: $domainName"
} catch {
    Write-Log "Systemstatus nicht ermittelbar: $_" "ERROR"
    exit 1
}

# ---------------- DC & LDAP Test ----------------
function Get-DomainController {
    try {
        return [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().FindDomainController().Name
    } catch {
        return $null
    }
}

function Test-Ldap {
    param([string]$DC)
    try {
        $root = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DC/RootDSE")
        return [bool]$root.Properties["defaultNamingContext"][0]
    } catch {
        return $false
    }
}

$dc = Get-DomainController
if (-not $dc) {
    Write-Log "Kein Domain Controller ermittelbar – Abbruch ohne Änderungen." "ERROR"
    exit 0
}

if (-not (Test-Ldap -DC $dc)) {
    Write-Log "LDAP nicht erreichbar – Abbruch ohne Änderungen." "ERROR"
    exit 0
}

Write-Log "Domain Controller erreichbar: $dc"

# ---------------- Domain SID Prefix ----------------
try {
    $root = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dc/RootDSE")
    $nc   = $root.Properties["defaultNamingContext"][0]
    $dom  = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dc/$nc")
    $sid  = New-Object System.Security.Principal.SecurityIdentifier($dom.Properties["objectSid"].Value, 0)
    $domainSidPrefix = $sid.Value
    Write-Log "Domain SID Prefix: $domainSidPrefix"
} catch {
    Write-Log "Domain SID nicht bestimmbar – Abbruch." "ERROR"
    exit 0
}

# ---------------- Lokale SIDs ----------------
$localSids = @()
try {
    $localSids = (Get-LocalUser).SID.Value
} catch {}

# ---------------- AD Lookup ----------------
function Get-ADUserStateBySID {
    param([string]$SID)

    try {
        $searcher = New-Object System.DirectoryServices.DirectorySearcher("LDAP://$dc/$nc")
        $searcher.Filter = "(objectSid=$SID)"
        $searcher.PropertiesToLoad.Add("sAMAccountName") | Out-Null
        $searcher.PropertiesToLoad.Add("userAccountControl") | Out-Null

        $r = $searcher.FindOne()
        if (-not $r) { return @{ Found = $false } }

        $uac = [int]$r.Properties["useraccountcontrol"][0]
        $enabled = -not ($uac -band 2)

        return @{
            Found   = $true
            Enabled = $enabled
            Sam     = $r.Properties["samaccountname"][0]
        }
    } catch {
        Write-Log "LDAP Fehler bei SID $SID – Abbruch." "ERROR"
        exit 0
    }
}

# ---------------- Profile Loop ----------------
$profiles = Get-WmiObject Win32_UserProfile | Where-Object {
    -not $_.Special -and $_.LocalPath
}

$deleted = 0
$skipped = 0

foreach ($p in $profiles) {
    $sid  = $p.SID
    $path = $p.LocalPath

    Write-Log "Prüfe $path ($sid)"

    if ($p.Loaded) {
        Write-Log "Profil geladen – übersprungen."
        $skipped++
        continue
    }

    if ($localSids -contains $sid) {
        Write-Log "Lokaler Benutzer – übersprungen."
        $skipped++
        continue
    }

    if ($sid -like "S-1-12-*") {
        Write-Log "AzureAD SID – übersprungen."
        $skipped++
        continue
    }

    if ($sid -notlike "$domainSidPrefix-*") {
        Write-Log "Nicht Domain-SID – übersprungen."
        $skipped++
        continue
    }

    $ad = Get-ADUserStateBySID -SID $sid

    if ($ad.Found -and $ad.Enabled) {
        Write-Log "AD-User aktiv ($($ad.Sam)) – behalten."
        $skipped++
        continue
    }

    Write-Log "MARKIERT ZUM LÖSCHEN: $($ad.Sam)" "WARN"

    if ($WhatIf) {
        $deleted++
        continue
    }

    try {
        $p.Delete() | Out-Null
        Write-Log "Profil via WMI gelöscht."
        if (Test-Path $path) {
            Remove-Item $path -Recurse -Force -ErrorAction Stop
            Write-Log "Ordner-Fallback erfolgreich."
        }
        $deleted++
    } catch {
        Write-Log "FEHLER beim Löschen $path : $_" "ERROR"
    }
}

Write-Log "=== Fertig ==="
Write-Log "Gelöscht: $deleted"
Write-Log "Übersprungen: $skipped"
Write-Log "Logdatei: $LogPath"
