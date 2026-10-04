# ============================================================
# CONTROLLO COMPLETO  (version 11 - solo analisi)
# ============================================================
# Novita' v11:
#   - Rimuove WiseCleaner dai trusted publishers (per ripristinare
#     WRCSkipUAC come SUSPICIOUS da usare come test)
#   - Alla fine dell'analisi, cancella repair.ps1 e repair.bat
#     se presenti nella cartella dello script
# ============================================================

# ------------------------------------------------------------
# CONFIGURAZIONE
# ------------------------------------------------------------

$trustedPublishers = @(
    "Microsoft Corporation",
    "Google LLC",
    "Mozilla Corporation",
    "Discord Inc.",
    "Spotify AB",
    "Telegram FZ-LLC",
    "Samsung Electronics Co., Ltd.",
    "Logitech Inc.",
    "Razer USA Ltd.",
    "Piriform Software Ltd",
    "PrivaZer"
)

$suspiciousPatterns = @(
    "autokms", "kmsauto", "kmspico", "kmseldi", "kmsserver",
    "sppextcomobjpatcher", "skippeduac", "skipuac", "kmsservice"
)

$unusualPathFragments = @(
    "\temp\", "\downloads\", "\appdata\local\temp\",
    "\users\public\", "\programdata\temp\"
)

$knownProtectedProcesses = @("MpDefenderCoreService")

$scriptFolder = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($scriptFolder)) {
    $scriptFolder = (Get-Location).Path
}

$reportFile       = Join-Path $scriptFolder "controllo-completo-report.json"
$whitelistFile    = Join-Path $scriptFolder "whitelist.txt"
$whitelistAddFile = Join-Path $scriptFolder "whitelist_from_web.txt"

$exportReport = $true

Clear-Host

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "   CONTROLLO COMPLETO (solo analisi)" -ForegroundColor Cyan
Write-Host "   Connessioni + Servizi + Attivita' pianificate" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# ------------------------------------------------------------
# VERIFICA PRIVILEGI
# ------------------------------------------------------------

$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$isAdmin   = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "[!] Script NON avviato come amministratore." -ForegroundColor Yellow
    Write-Host "    Alcuni elementi risulteranno UNVERIFIABLE." -ForegroundColor Yellow
    Write-Host ""
}

# ------------------------------------------------------------
# FUNZIONE: normalizza una stringa per match whitelist
# ------------------------------------------------------------
function Get-WlNormalized {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return "" }
    $t = $Text.Trim().ToLowerInvariant().Replace("\", "/").Trim("/")
    return $t
}

# ------------------------------------------------------------
# FUNZIONE: merge whitelist_from_web.txt in whitelist.txt
# ------------------------------------------------------------
function Merge-WhitelistFromWeb {
    param([string]$AddFile, [string]$TargetFile)

    if (-not (Test-Path -LiteralPath $AddFile)) { return }

    Write-Host "------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host "[WHITELIST] Trovato whitelist_from_web.txt, elaborazione..." -ForegroundColor Cyan
    Write-Host "------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host ""

    $rawLines = @(
        Get-Content -LiteralPath $AddFile -Encoding UTF8 -ErrorAction SilentlyContinue |
        Where-Object { $_ -and -not $_.StartsWith("#") -and $_.Trim() -ne "" }
    )

    $hashLines = @()
    $nameLines = @()
    $skipped   = @()

    foreach ($line in $rawLines) {

        if ($line.TrimStart().StartsWith("-")) {
            $skipped += $line
            continue
        }

        $parts = $line.Split("|")

        if ($parts.Count -ge 5 -and $parts[0].Trim() -eq "NAME") {
            if (-not [string]::IsNullOrWhiteSpace($parts[3])) {
                $nameLines += $line
            } else {
                $skipped += $line
            }
            continue
        }

        if ($parts.Count -ge 4) {
            $hash = $parts[0].Trim()
            if ($hash -match '^[A-Fa-f0-9]{64}$' -and -not [string]::IsNullOrWhiteSpace($parts[1])) {
                $hashLines += $line
                continue
            }
        }

        $skipped += $line
    }

    Write-Host ("       Righe HASH valide : {0}" -f $hashLines.Count) -ForegroundColor Cyan
    Write-Host ("       Righe NAME valide : {0}" -f $nameLines.Count) -ForegroundColor Cyan
    Write-Host ("       Righe scartate    : {0}" -f $skipped.Count)  -ForegroundColor DarkGray

    if ($skipped.Count -gt 0) {
        Write-Host ""
        Write-Host "       Righe scartate:" -ForegroundColor DarkGray
        foreach ($s in $skipped) { Write-Host ("         {0}" -f $s) -ForegroundColor DarkGray }
    }

    if ($hashLines.Count -eq 0 -and $nameLines.Count -eq 0) {
        Write-Host ""
        Write-Host "[SKIP] Nessuna riga valida. whitelist.txt NON modificato." -ForegroundColor DarkGray
        Write-Host "       whitelist_from_web.txt eliminato." -ForegroundColor DarkGray
        try { Remove-Item -LiteralPath $AddFile -Force -ErrorAction Stop } catch { }
        Write-Host ""
        return
    }

    if (-not (Test-Path -LiteralPath $TargetFile)) {
        $header = @(
            "# WHITELIST di controllo-completo.ps1",
            "# Formato HASH : SHA256|Path|Process|DateAdded",
            "# Formato NAME : NAME|Type|Path|Name|DateAdded",
            "# Un elemento HASH e' approvato se path E hash coincidono.",
            "# Un elemento NAME e' approvato se Type, Path e Name coincidono."
        )
        Set-Content -LiteralPath $TargetFile -Value $header -Encoding UTF8
    }

    $allNew = @()
    if ($hashLines.Count -gt 0) { $allNew += $hashLines }
    if ($nameLines.Count -gt 0) { $allNew += $nameLines }

    Add-Content -LiteralPath $TargetFile -Value $allNew -Encoding UTF8

    Write-Host "[OK] Aggiunte $($allNew.Count) voci a whitelist.txt." -ForegroundColor Green

    try {
        Remove-Item -LiteralPath $AddFile -Force -ErrorAction Stop
        Write-Host "     whitelist_from_web.txt eliminato." -ForegroundColor DarkGray
    } catch { }
    Write-Host ""
}

# ------------------------------------------------------------
# FUNZIONE: rimuove repair.ps1 e repair.bat (se presenti)
# ------------------------------------------------------------
function Remove-RepairFiles {
    param([string]$Folder)

    $repairPs1 = Join-Path $Folder "repair.ps1"
    $repairBat = Join-Path $Folder "repair.bat"

    $removed = @()

    if (Test-Path -LiteralPath $repairPs1) {
        try {
            Remove-Item -LiteralPath $repairPs1 -Force -ErrorAction Stop
            $removed += "repair.ps1"
        } catch { }
    }

    if (Test-Path -LiteralPath $repairBat) {
        try {
            Remove-Item -LiteralPath $repairBat -Force -ErrorAction Stop
            $removed += "repair.bat"
        } catch { }
    }

    if ($removed.Count -gt 0) {
        Write-Host ""
        Write-Host "[REPAIR] File temporanei rimossi: $($removed -join ', ')" -ForegroundColor DarkGray
    }
}

# ------------------------------------------------------------
# FUNZIONI DI SUPPORTO
# ------------------------------------------------------------

function Test-PrivateOrLocalIP {
    param([string]$IP)
    try { $address = [System.Net.IPAddress]::Parse($IP) } catch { return $false }

    if (($address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) -and $address.IsIPv4MappedToIPv6) {
        $address = $address.MapToIPv4()
    }
    if ($address.IsLoopback) { return $true }

    if ($address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
        $b = $address.GetAddressBytes()
        if ($b[0] -eq 0)   { return $true }
        if ($b[0] -eq 10)  { return $true }
        if (($b[0] -eq 100) -and (($b[1] -band 0xC0) -eq 64)) { return $true }
        if ($b[0] -eq 127) { return $true }
        if (($b[0] -eq 169) -and ($b[1] -eq 254)) { return $true }
        if (($b[0] -eq 172) -and ($b[1] -ge 16) -and ($b[1] -le 31)) { return $true }
        if (($b[0] -eq 192) -and ($b[1] -eq 168)) { return $true }
        if ($b[0] -ge 224) { return $true }
    }
    else {
        $b = $address.GetAddressBytes()
        if ($address.Equals([System.Net.IPAddress]::IPv6Any)) { return $true }
        if (($b[0] -band 0xFE) -eq 0xFC) { return $true }
        if (($b[0] -eq 0xFE) -and (($b[1] -band 0xC0) -eq 0x80)) { return $true }
        if ($b[0] -eq 0xFF) { return $true }
    }
    return $false
}

function Test-SuspiciousName {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    $lower = $Text.ToLowerInvariant()
    foreach ($pattern in $suspiciousPatterns) {
        if ($lower -like "*$pattern*") { return $true }
    }
    return $false
}

function Test-UnusualPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path -eq "N/A") { return $false }
    $lower = $Path.ToLowerInvariant()
    foreach ($frag in $unusualPathFragments) {
        if ($lower -like "*$frag*") { return $true }
    }
    return $false
}

function Get-FileAnalysis {
    param([string]$Path)

    $result = [PSCustomObject]@{
        Exists = $false; Signature = "N/A"; Publisher = "N/A"
        Company = "N/A"; Version = "N/A"; Hash = "N/A"
    }

    if ([string]::IsNullOrWhiteSpace($Path) -or $Path -eq "N/A") { return $result }

    $cleanPath = $Path.Trim('"')
    if ($cleanPath -match '^(.+?\.exe)') { $cleanPath = $matches[1] }

    if (-not (Test-Path -LiteralPath $cleanPath)) { return $result }
    $result.Exists = $true

    try {
        $vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($cleanPath)
        if ($vi.CompanyName) { $result.Company = $vi.CompanyName }
        if ($vi.FileVersion) { $result.Version = $vi.FileVersion }
    } catch { }

    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $cleanPath -ErrorAction SilentlyContinue
        if ($sig) {
            $result.Signature = switch ($sig.Status) {
                "Valid"        { "Valid" }
                "NotSigned"    { "Unsigned" }
                "NotTrusted"   { "Untrusted" }
                "HashMismatch" { "Invalid hash" }
                default        { "Other ($($sig.Status))" }
            }
            if ($sig.SignerCertificate) {
                try {
                    $result.Publisher = $sig.SignerCertificate.GetNameInfo(
                        [System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
                } catch { }
            }
        }
    } catch { }

    try {
        $result.Hash = (Get-FileHash -LiteralPath $cleanPath -Algorithm SHA256 -ErrorAction Stop).Hash
    } catch { }

    return $result
}

function Get-Evaluation {
    param([string]$Name, [string]$Path, [object]$FileInfo)

    if ($FileInfo.Signature -eq "Valid" -and ($trustedPublishers -contains $FileInfo.Publisher)) {
        return "Normal"
    }
    if (Test-SuspiciousName $Name) { return "SUSPICIOUS (known name)" }
    if (Test-SuspiciousName $Path) { return "SUSPICIOUS (known path)" }
    if (-not $Path -or $Path -eq "N/A") { return "UNVERIFIABLE" }
    if (Test-UnusualPath $Path) {
        if ($FileInfo.Signature -eq "Valid") { return "TO CHECK (path)" }
        else { return "SUSPICIOUS (path/signature)" }
    }
    if ($FileInfo.Signature -ne "Valid") { return "TO CHECK (signature)" }
    return "Normal"
}

function Get-StatusCounts {
    param([object[]]$Items)
    $c = [PSCustomObject]@{
        Total = $Items.Count; Normal = 0; NormalDisab = 0; NormalSys = 0
        Whitelist = 0; ToCheck = 0; Unverifiable = 0; Suspicious = 0
    }
    foreach ($it in $Items) {
        $s = $it.Status
        if     ($s -like "Normal (system task)*") { $c.NormalSys++ }
        elseif ($s -like "Normal (disabled)*")    { $c.NormalDisab++ }
        elseif ($s -like "Normal*")               { $c.Normal++ }
        elseif ($s -eq "Whitelist")               { $c.Whitelist++ }
        elseif ($s -like "TO CHECK*")             { $c.ToCheck++ }
        elseif ($s -like "UNVERIFIABLE*")         { $c.Unverifiable++ }
        elseif ($s -like "SUSPICIOUS*")           { $c.Suspicious++ }
    }
    return $c
}

function Write-SectionSummary {
    param([string]$Title, [object]$Counts)
    Write-Host ("  {0,-14}: {1,4} totali" -f $Title, $Counts.Total) -ForegroundColor White
    $n = $Counts.Normal + $Counts.NormalDisab + $Counts.NormalSys
    Write-Host ("      Normal           : {0,4}" -f $n) -ForegroundColor Green
    if ($Counts.NormalDisab -gt 0) { Write-Host ("        (di cui disabled): {0,4}" -f $Counts.NormalDisab) -ForegroundColor DarkGray }
    if ($Counts.NormalSys   -gt 0) { Write-Host ("        (di cui system)  : {0,4}" -f $Counts.NormalSys)   -ForegroundColor DarkGray }
    Write-Host ("      Whitelist        : {0,4}" -f $Counts.Whitelist)    -ForegroundColor DarkGray
    Write-Host ("      TO CHECK         : {0,4}" -f $Counts.ToCheck)      -ForegroundColor Yellow
    Write-Host ("      UNVERIFIABLE     : {0,4}" -f $Counts.Unverifiable) -ForegroundColor Yellow
    Write-Host ("      SUSPICIOUS       : {0,4}" -f $Counts.Suspicious)   -ForegroundColor Red
}

# ============================================================
# MERGE WHITELIST_FROM_WEB.TXT
# ============================================================

Merge-WhitelistFromWeb -AddFile $whitelistAddFile -TargetFile $whitelistFile

# ------------------------------------------------------------
# CARICA WHITELIST
# ------------------------------------------------------------

$wlHash = @{}
$wlName = @{}

if (Test-Path -LiteralPath $whitelistFile) {
    $lines = Get-Content -LiteralPath $whitelistFile -Encoding UTF8 -ErrorAction SilentlyContinue
    foreach ($line in $lines) {
        $line = $line.Trim()
        if (($line -eq "") -or $line.StartsWith("#")) { continue }
        $parts = $line.Split("|")

        if ($parts.Count -ge 5 -and $parts[0].Trim() -eq "NAME") {
            $type = $parts[1].Trim().ToLowerInvariant()
            $path = Get-WlNormalized $parts[2]
            $name = Get-WlNormalized $parts[3]
            $wlName["$type|$path|$name"] = $true
            continue
        }

        if ($parts.Count -lt 4) { continue }
        $h = $parts[0].Trim().ToUpperInvariant()
        if ($h -notmatch '^[A-Fa-f0-9]{64}$') { continue }
        $p = Get-WlNormalized $parts[1]
        $wlHash["$p|$h"] = $true
    }
    Write-Host "Whitelist caricata: $($wlHash.Count) HASH, $($wlName.Count) NAME." -ForegroundColor DarkGray
    Write-Host ""
}

# ============================================================
# SEZIONE 1: CONNESSIONI TCP ESTERNE
# ============================================================

Write-Host "[1/3] Analisi CONNESSIONI TCP esterne..." -ForegroundColor Cyan

$connections = @(
    Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
    Where-Object { -not (Test-PrivateOrLocalIP $_.RemoteAddress) }
)

Write-Host "  Trovate $($connections.Count) connessioni esterne." -ForegroundColor DarkGray

$processCache = @{}

$connectionResults = foreach ($conn in $connections) {

    $processId = $conn.OwningProcess

    if (-not $processCache.ContainsKey($processId)) {

        $processObj = Get-Process -Id $processId -ErrorAction SilentlyContinue
        $cimProcess = Get-CimInstance Win32_Process -Filter "ProcessId=$processId" -ErrorAction SilentlyContinue

        $processName = if ($processObj) { $processObj.Name } else { "N/A" }

        $path = $null
        if ($cimProcess -and $cimProcess.ExecutablePath) { $path = $cimProcess.ExecutablePath }
        elseif ($processObj -and $processObj.Path) { $path = $processObj.Path }
        if ([string]::IsNullOrWhiteSpace($path)) { $path = "N/A" }

        $fileInfo = Get-FileAnalysis -Path $path
        $status = Get-Evaluation -Name $processName -Path $path -FileInfo $fileInfo

        if (($path -eq "N/A") -and $isAdmin -and ($knownProtectedProcesses -contains $processName)) {
            $status = "Normal (protected process)"
        }

        if ($status -ne "Normal" -and $fileInfo.Hash -ne "N/A") {
            $key = (Get-WlNormalized $path) + "|" + $fileInfo.Hash.ToUpperInvariant()
            if ($wlHash.ContainsKey($key)) { $status = "Whitelist" }
        }

        $processCache[$processId] = [PSCustomObject]@{
            Process   = $processName
            Path      = $path
            Company   = $fileInfo.Company
            Version   = $fileInfo.Version
            Signature = $fileInfo.Signature
            Publisher = $fileInfo.Publisher
            Status    = $status
            Hash      = $fileInfo.Hash
        }
    }

    $info = $processCache[$processId]

    [PSCustomObject]@{
        Type = "Connection"; Name = $info.Process; DisplayName = "N/A"
        PID = $processId; Remote_IP = $conn.RemoteAddress; Remote_Port = $conn.RemotePort
        Local_Port = $conn.LocalPort; State = "Established"; StartMode = "N/A"
        Status = $info.Status; Signature = $info.Signature; Publisher = $info.Publisher
        Company = $info.Company; Version = $info.Version; Hash = $info.Hash
        Path = $info.Path; RawCommand = "N/A"
    }
}

$connectionResults = @($connectionResults | Sort-Object Name, Remote_IP, Remote_Port, PID -Unique)

# ============================================================
# SEZIONE 2: SERVIZI
# ============================================================

Write-Host "[2/3] Analisi SERVIZI..." -ForegroundColor Cyan

$services = @(Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue)
Write-Host "  Trovati $($services.Count) servizi." -ForegroundColor DarkGray

$serviceResults = foreach ($svc in $services) {

    $name    = $svc.Name
    $display = $svc.DisplayName
    $path    = if ([string]::IsNullOrWhiteSpace($svc.PathName)) { "N/A" } else { $svc.PathName }

    $fileInfo = Get-FileAnalysis -Path $path
    $status   = Get-Evaluation -Name "$name $display" -Path $path -FileInfo $fileInfo

    if (($svc.State -eq "Stopped") -and ($svc.StartMode -eq "Disabled")) {
        if ($status -ne "Normal" -and $status -ne "Normal (disabled)") {
            $status = "Normal (disabled)"
        }
    }

    if ($status -ne "Normal" -and $status -ne "Normal (disabled)" -and $fileInfo.Hash -ne "N/A") {
        $key = (Get-WlNormalized $path) + "|" + $fileInfo.Hash.ToUpperInvariant()
        if ($wlHash.ContainsKey($key)) { $status = "Whitelist" }
    }

    if ($status -ne "Normal" -and $status -ne "Normal (disabled)" -and $status -ne "Whitelist") {
        $wkey = "service|" + (Get-WlNormalized $name) + "|" + (Get-WlNormalized $name)
        if ($wlName.ContainsKey($wkey)) { $status = "Whitelist" }
    }

    [PSCustomObject]@{
        Type = "Service"; Name = $name; DisplayName = $display
        PID = "N/A"; Remote_IP = "N/A"; Remote_Port = "N/A"; Local_Port = "N/A"
        State = $svc.State; StartMode = $svc.StartMode
        Status = $status; Signature = $fileInfo.Signature; Publisher = $fileInfo.Publisher
        Company = $fileInfo.Company; Version = $fileInfo.Version; Hash = $fileInfo.Hash
        Path = $path; RawCommand = "N/A"
    }
}

# ============================================================
# SEZIONE 3: ATTIVITA' PIANIFICATE
# ============================================================

Write-Host "[3/3] Analisi ATTIVITA' PIANIFICATE..." -ForegroundColor Cyan

$tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue)
Write-Host "  Trovate $($tasks.Count) attivita'." -ForegroundColor DarkGray

$taskResults = foreach ($task in $tasks) {

    $name = $task.TaskName
    $path = $task.TaskPath

    $exePath    = "N/A"
    $rawCommand = "N/A"

    if ($task.Actions -and $task.Actions.Count -gt 0) {
        $action = $task.Actions[0]
        if ($action.Execute) {
            $exePath = $action.Execute
            $rawCommand = $action.Execute
            if ($action.Arguments) { $rawCommand = "$rawCommand $($action.Arguments)" }
        }
    }

    $fileInfo = Get-FileAnalysis -Path $exePath
    $status   = Get-Evaluation -Name "$name $path" -Path $exePath -FileInfo $fileInfo

    if (($path -like "\Microsoft\Windows\*") -and ($exePath -eq "N/A") -and ($status -eq "UNVERIFIABLE")) {
        $status = "Normal (system task)"
    }
    if ($task.State -eq "Disabled") {
        if ($status -ne "Normal" -and $status -ne "Normal (disabled)") {
            $status = "Normal (disabled)"
        }
    }

    if ($status -ne "Normal" -and $status -ne "Normal (disabled)" -and $status -ne "Normal (system task)" -and $fileInfo.Hash -ne "N/A") {
        $key = (Get-WlNormalized $exePath) + "|" + $fileInfo.Hash.ToUpperInvariant()
        if ($wlHash.ContainsKey($key)) { $status = "Whitelist" }
    }

    if ($status -ne "Normal" -and $status -ne "Normal (disabled)" -and $status -ne "Normal (system task)" -and $status -ne "Whitelist") {
        $wkey = "task|" + (Get-WlNormalized $path) + "|" + (Get-WlNormalized $name)
        if ($wlName.ContainsKey($wkey)) { $status = "Whitelist" }
    }

    [PSCustomObject]@{
        Type = "Task"; Name = $name; DisplayName = $path
        PID = "N/A"; Remote_IP = "N/A"; Remote_Port = "N/A"; Local_Port = "N/A"
        State = $task.State
        StartMode = ($task.Triggers | ForEach-Object { $_.CimClass.CimClassName }) -join ", "
        Status = $status; Signature = $fileInfo.Signature; Publisher = $fileInfo.Publisher
        Company = $fileInfo.Company; Version = $fileInfo.Version; Hash = $fileInfo.Hash
        Path = $exePath; RawCommand = $rawCommand
    }
}

# ============================================================
# RIEPILOGO
# ============================================================

$connCounts = Get-StatusCounts -Items $connectionResults
$svcCounts  = Get-StatusCounts -Items $serviceResults
$taskCounts = Get-StatusCounts -Items $taskResults
$allResults = @($connectionResults) + @($serviceResults) + @($taskResults)
$totCounts  = Get-StatusCounts -Items $allResults

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "                 RIEPILOGO" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "--- Connessioni TCP esterne ---" -ForegroundColor Cyan
Write-SectionSummary -Title "Connessioni" -Counts $connCounts
Write-Host ""
Write-Host "--- Servizi di Windows ---" -ForegroundColor Cyan
Write-SectionSummary -Title "Servizi" -Counts $svcCounts
Write-Host ""
Write-Host "--- Attivita' pianificate ---" -ForegroundColor Cyan
Write-SectionSummary -Title "Attivita'" -Counts $taskCounts
Write-Host ""
Write-Host "--- TOTALE COMPLESSIVO ---" -ForegroundColor Cyan
Write-Host ("  {0,4} elementi analizzati" -f $totCounts.Total) -ForegroundColor White
$n = $totCounts.Normal + $totCounts.NormalDisab + $totCounts.NormalSys
Write-Host ("      Normal           : {0,4}" -f $n) -ForegroundColor Green
Write-Host ("      Whitelist        : {0,4}" -f $totCounts.Whitelist)    -ForegroundColor DarkGray
Write-Host ("      TO CHECK         : {0,4}" -f $totCounts.ToCheck)      -ForegroundColor Yellow
Write-Host ("      UNVERIFIABLE     : {0,4}" -f $totCounts.Unverifiable) -ForegroundColor Yellow
Write-Host ("      SUSPICIOUS       : {0,4}" -f $totCounts.Suspicious)   -ForegroundColor Red
Write-Host ""

# ============================================================
# REPORT JSON
# ============================================================

if ($exportReport) {
    try {
        $report = [ordered]@{
            schema = "controllo-completo/1"
            generated = (Get-Date).ToString("yyyy-MM-dd'T'HH:mm:sszzz")
            isAdmin = $isAdmin
            totalConnections = $connectionResults.Count
            totalServices = $services.Count
            totalTasks = $tasks.Count
            connections = @($connectionResults)
            services = @($serviceResults)
            tasks = @($taskResults)
        }
        $json = ConvertTo-Json -InputObject $report -Depth 4
        [System.IO.File]::WriteAllText($reportFile, $json, (New-Object System.Text.UTF8Encoding($false)))
        Write-Host "Report JSON salvato: $reportFile" -ForegroundColor DarkGray
    } catch {
        Write-Host "[WARNING] Impossibile salvare il report: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# ============================================================
# RIMOZIONE FILE REPAIR (se presenti)
# ============================================================

Remove-RepairFiles -Folder $scriptFolder

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Analisi completata. Nessuna azione eseguita." -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""