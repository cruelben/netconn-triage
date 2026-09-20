# ============================================================
# TCP CONNECTION AND PROCESS CHECK  (version 3)
# ============================================================
# Lists ESTABLISHED TCP connections to external IPs and, for each
# process involved, checks its path and digital signature.
#
# Possible outcomes (Status column):
#   Normal            - valid signature and ordinary path
#   Whitelist         - process you approved yourself (whitelist.txt)
#   TO CHECK          - invalid signature or unusual path
#   SUSPICIOUS        - unusual path AND invalid signature
#   UNVERIFIABLE      - program path cannot be read
#                       (running as administrator often fixes this)
#
# If SUSPICIOUS processes are found, the script asks:
#   1) Terminate all of them? (this also closes their connections)
#        YES -> terminates the processes; you can then move their
#               files to quarantine (nothing is deleted)
#        NO  -> for each process, asks whether to add it to the
#               whitelist (whitelist.txt, in the script folder)
#
# The whitelist stores the PATH + SHA256 HASH of the file: if the
# file is replaced or modified, it is flagged again.
#
# LIMITATIONS: this is a snapshot of the moment. It does not see
# UDP connections (e.g. browser QUIC/HTTP3) or very short-lived
# ones. A signed program, or code injected into a legitimate
# process, would still be reported as "Normal".
# ============================================================

# ------------------------------------------------------------
# CONFIGURATION
# ------------------------------------------------------------

# Publishers you trust. If a program located in \AppData\ has a
# VALID signature from one of these publishers, it is considered
# Normal (avoids false positives for Discord, Spotify, Chrome...).
# The exact name is shown in the "Publisher" column of the details.
$trustedPublishers = @(
    "Microsoft Corporation",
    "Google LLC",
    "Mozilla Corporation",
    "Discord Inc.",
    "Spotify AB",
    "Telegram FZ-LLC"
)

# Protected system processes whose path cannot be read even as
# administrator. They are considered Normal ONLY if the script is
# running as administrator.
$knownProtectedProcesses = @(
    "MpDefenderCoreService"
)

# Processes that the cleanup function NEVER terminates
# (when they are located in System32)
$criticalProcesses = @(
    "system", "idle", "registry", "smss", "csrss", "wininit",
    "winlogon", "services", "lsass", "svchost", "explorer",
    "dwm", "fontdrvhost", "lsm"
)

# Script folder: whitelist.txt and the Quarantine folder are saved here
$scriptFolder = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($scriptFolder)) {
    $scriptFolder = (Get-Location).Path
}

$whitelistFile = Join-Path $scriptFolder "whitelist.txt"
$quarantineFolder = Join-Path $scriptFolder "Quarantine"
$quarantineIndexFile = Join-Path $quarantineFolder "quarantine.txt"

Clear-Host

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "   TCP CONNECTION AND PROCESS CHECK" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# ------------------------------------------------------------
# ADMINISTRATOR PRIVILEGES CHECK
# ------------------------------------------------------------
# Without elevated privileges, the path of many system processes
# cannot be read and elevated processes cannot be terminated.

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$isAdmin = $principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

if (-not $isAdmin) {
    Write-Host "[!] Script was NOT started as administrator." -ForegroundColor Yellow
    Write-Host "    Some processes will be reported as 'UNVERIFIABLE' and" -ForegroundColor Yellow
    Write-Host "    you will not be able to terminate elevated ones." -ForegroundColor Yellow
    Write-Host "    For a complete analysis: right-click run.bat" -ForegroundColor Yellow
    Write-Host "    > Run as administrator." -ForegroundColor Yellow
    Write-Host ""
}

# ------------------------------------------------------------
# FUNCTION: checks whether an IP is local, private or multicast
# ------------------------------------------------------------
function Test-PrivateOrLocalIP {

    param (
        [string]$IP
    )

    try {
        $address = [System.Net.IPAddress]::Parse($IP)
    }
    catch {
        return $false
    }

    # IPv4 written in IPv6 format (::ffff:a.b.c.d):
    # convert it to a plain IPv4 address before checking it
    if (
        ($address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) -and
        $address.IsIPv4MappedToIPv6
    ) {
        $address = $address.MapToIPv4()
    }

    # Loopback (127.0.0.1 / ::1)
    if ($address.IsLoopback) {
        return $true
    }

    # --------------------------------------------------------
    # IPv4
    # --------------------------------------------------------
    if ($address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {

        $b = $address.GetAddressBytes()

        # 0.0.0.0/8 (unspecified address)
        if ($b[0] -eq 0) {
            return $true
        }

        # 10.0.0.0/8
        if ($b[0] -eq 10) {
            return $true
        }

        # 100.64.0.0/10 (CGNAT, used e.g. by Tailscale)
        if (($b[0] -eq 100) -and (($b[1] -band 0xC0) -eq 64)) {
            return $true
        }

        # 127.0.0.0/8
        if ($b[0] -eq 127) {
            return $true
        }

        # 169.254.0.0/16 (link-local)
        if (($b[0] -eq 169) -and ($b[1] -eq 254)) {
            return $true
        }

        # 172.16.0.0 - 172.31.255.255
        if (
            ($b[0] -eq 172) -and
            ($b[1] -ge 16) -and
            ($b[1] -le 31)
        ) {
            return $true
        }

        # 192.168.0.0/16
        if (
            ($b[0] -eq 192) -and
            ($b[1] -eq 168)
        ) {
            return $true
        }

        # 224.0.0.0/4 multicast (and above: reserved/broadcast)
        if ($b[0] -ge 224) {
            return $true
        }
    }

    # --------------------------------------------------------
    # IPv6
    # --------------------------------------------------------
    else {

        $b = $address.GetAddressBytes()

        # :: (unspecified address)
        if ($address.Equals([System.Net.IPAddress]::IPv6Any)) {
            return $true
        }

        # FC00::/7 (unique local)
        if (($b[0] -band 0xFE) -eq 0xFC) {
            return $true
        }

        # FE80::/10 (link-local)
        if (
            ($b[0] -eq 0xFE) -and
            (($b[1] -band 0xC0) -eq 0x80)
        ) {
            return $true
        }

        # FF00::/8 multicast
        if ($b[0] -eq 0xFF) {
            return $true
        }
    }

    return $false
}

# ------------------------------------------------------------
# FUNCTION: YES/NO question (repeats until the answer is valid)
# ------------------------------------------------------------
function Read-YesNo {

    param (
        [string]$Question
    )

    while ($true) {

        $answer = Read-Host "$Question (Y/N)"

        if ($null -eq $answer) {
            return $false
        }

        $answer = $answer.Trim().ToLowerInvariant()

        if (@("y", "yes") -contains $answer) {
            return $true
        }

        if (@("n", "no") -contains $answer) {
            return $false
        }

        Write-Host "Invalid answer: type Y or N." -ForegroundColor Yellow
    }
}

# ------------------------------------------------------------
# FUNCTION: adds an entry to whitelist.txt
# Line format: SHA256|Path|Process|DateAdded
# ------------------------------------------------------------
function Add-WhitelistEntry {

    param (
        [string]$Hash,
        [string]$FilePath,
        [string]$ProcessName
    )

    # If the file does not exist, create it with a short header
    if (-not (Test-Path -LiteralPath $whitelistFile)) {

        $header = @(
            "# WHITELIST of controllo-connessioni.ps1",
            "# Format: SHA256|Path|Process|DateAdded",
            "# A process is approved only if BOTH path and hash match.",
            "# To remove an entry, simply delete its line."
        )

        Set-Content `
            -LiteralPath $whitelistFile `
            -Value $header `
            -Encoding UTF8
    }

    $line = "{0}|{1}|{2}|{3}" -f `
        $Hash.ToUpperInvariant(),
        $FilePath,
        $ProcessName,
        (Get-Date -Format "yyyy-MM-dd HH:mm")

    Add-Content `
        -LiteralPath $whitelistFile `
        -Value $line `
        -Encoding UTF8
}

# ------------------------------------------------------------
# LOAD THE WHITELIST (if it exists)
# ------------------------------------------------------------
# $whitelistEntries : key "path|HASH" -> approved
# $whitelistPaths   : paths already present (with any hash),
#                     used to flag modified files

$whitelistEntries = @{}
$whitelistPaths = @{}

if (Test-Path -LiteralPath $whitelistFile) {

    $whitelistLines = Get-Content `
        -LiteralPath $whitelistFile `
        -Encoding UTF8 `
        -ErrorAction SilentlyContinue

    foreach ($line in $whitelistLines) {

        $line = $line.Trim()

        # Skip empty lines and comments
        if (($line -eq "") -or $line.StartsWith("#")) {
            continue
        }

        $parts = $line.Split("|")

        if ($parts.Count -lt 2) {
            continue
        }

        $entryHash = $parts[0].Trim().ToUpperInvariant()
        $entryPath = $parts[1].Trim().ToLowerInvariant()

        $whitelistEntries[$entryPath + "|" + $entryHash] = $true
        $whitelistPaths[$entryPath] = $true
    }

    Write-Host "Whitelist loaded: $($whitelistEntries.Count) entries." -ForegroundColor DarkGray
}

Write-Host "Analyzing connections..." -ForegroundColor Yellow
Write-Host ""

# ------------------------------------------------------------
# GET ESTABLISHED TCP CONNECTIONS TO EXTERNAL IPs
# ------------------------------------------------------------

$connections = @(
    Get-NetTCPConnection `
        -State Established `
        -ErrorAction SilentlyContinue |
    Where-Object {
        -not (Test-PrivateOrLocalIP $_.RemoteAddress)
    }
)

# ------------------------------------------------------------
# NO CONNECTIONS
# ------------------------------------------------------------

if ($connections.Count -eq 0) {

    Write-Host "[OK] No active external TCP connection found." -ForegroundColor Green
    Write-Host ""
    Write-Host "Analysis complete." -ForegroundColor Yellow

    return
}

$totalConnections = $connections.Count

Write-Host "Found $totalConnections external TCP connections." -ForegroundColor Green
Write-Host ""

# ------------------------------------------------------------
# PROCESS CACHE
# (each process is analyzed only once)
# ------------------------------------------------------------

$processCache = @{}

# ------------------------------------------------------------
# CONNECTION ANALYSIS
# ------------------------------------------------------------

$results = foreach ($conn in $connections) {

    # IMPORTANT:
    # Do not use $pid: it is an automatic PowerShell variable.
    $processId = $conn.OwningProcess

    # --------------------------------------------------------
    # Get process information (only if not already cached)
    # --------------------------------------------------------

    if (-not $processCache.ContainsKey($processId)) {

        $processObj = Get-Process `
            -Id $processId `
            -ErrorAction SilentlyContinue

        $cimProcess = Get-CimInstance `
            Win32_Process `
            -Filter "ProcessId=$processId" `
            -ErrorAction SilentlyContinue

        # Process name
        if ($processObj) {
            $processName = $processObj.Name
        }
        else {
            $processName = "N/A"
        }

        # ----------------------------------------------------
        # Executable path
        # ----------------------------------------------------

        $path = $null

        if ($cimProcess -and $cimProcess.ExecutablePath) {
            $path = $cimProcess.ExecutablePath
        }
        elseif ($processObj -and $processObj.Path) {
            $path = $processObj.Path
        }

        if ([string]::IsNullOrWhiteSpace($path)) {
            $path = "N/A"
        }

        # Does the file exist and is it readable?
        # (-LiteralPath: also handles paths containing [ ] in the name)
        $fileExists = ($path -ne "N/A") -and (Test-Path -LiteralPath $path)

        # ----------------------------------------------------
        # File information (company and version)
        # ----------------------------------------------------

        $company = "N/A"
        $version = "N/A"

        if ($fileExists) {

            try {

                $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($path)

                if ($versionInfo.CompanyName) {
                    $company = $versionInfo.CompanyName
                }

                if ($versionInfo.FileVersion) {
                    $version = $versionInfo.FileVersion
                }

            }
            catch {
                # Ignore: they stay "N/A"
            }
        }

        # ----------------------------------------------------
        # Digital signature
        # ----------------------------------------------------

        $signature = "N/A"
        $publisher = "N/A"

        if ($fileExists) {

            try {

                $sigInfo = Get-AuthenticodeSignature `
                    -LiteralPath $path `
                    -ErrorAction SilentlyContinue

                if ($sigInfo) {

                    $signature = switch ($sigInfo.Status) {

                        "Valid"        { "Valid" }
                        "NotSigned"    { "Unsigned" }
                        "NotTrusted"   { "Untrusted" }
                        "HashMismatch" { "Invalid hash" }

                        # Any other status (e.g. UnknownError):
                        # do NOT consider it valid
                        default {
                            "Other (" + [string]$sigInfo.Status + ")"
                        }
                    }

                    if ($sigInfo.SignerCertificate) {

                        try {

                            $publisher =
                                $sigInfo.SignerCertificate.GetNameInfo(
                                    [System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName,
                                    $false
                                )

                        }
                        catch {
                            $publisher = "N/A"
                        }
                    }
                }

            }
            catch {
                $signature = "N/A"
            }
        }

        # ----------------------------------------------------
        # Evaluation
        # ----------------------------------------------------

        $status = "Normal"
        $hash = "N/A"
        $note = ""

        if ($path -eq "N/A") {

            # Path cannot be read. If I am administrator and it is a
            # known protected process (e.g. Defender), consider it
            # Normal; otherwise I cannot judge it.
            if (
                $isAdmin -and
                ($knownProtectedProcesses -contains $processName)
            ) {
                $status = "Normal (protected process)"
            }
            else {
                $status = "UNVERIFIABLE"
            }
        }
        else {

            $pathLower = $path.ToLowerInvariant()
            $signatureValid = ($signature -eq "Valid")

            # Very unusual folders for a program
            $inTempDownloads = (
                $pathLower -like "*\temp\*" -or
                $pathLower -like "*\downloads\*"
            )

            # AppData: also used by many legitimate apps
            $inAppData = ($pathLower -like "*\appdata\*")

            # Is the publisher in the trusted list?
            $trustedPublisher = ($trustedPublishers -contains $publisher)

            if ($inTempDownloads) {

                if ($signatureValid) {
                    $status = "TO CHECK (path)"
                }
                else {
                    $status = "SUSPICIOUS (path/signature)"
                }

            }
            elseif ($inAppData) {

                if ($signatureValid -and $trustedPublisher) {
                    $status = "Normal"
                }
                elseif ($signatureValid) {
                    $status = "TO CHECK (path)"
                }
                else {
                    $status = "SUSPICIOUS (path/signature)"
                }

            }
            elseif (-not $signatureValid) {

                # Ordinary path but missing or invalid signature
                $status = "TO CHECK (signature)"
            }
            else {

                $status = "Normal"
            }

            # ------------------------------------------------
            # If the process is NOT "Normal", compute the file
            # hash and check the whitelist (path + hash)
            # ------------------------------------------------

            if ($status -ne "Normal") {

                if ($fileExists) {

                    try {
                        $hash = (
                            Get-FileHash `
                                -LiteralPath $path `
                                -Algorithm SHA256 `
                                -ErrorAction Stop
                        ).Hash
                    }
                    catch {
                        $hash = "N/A"
                    }
                }

                if ($hash -ne "N/A") {

                    $key = $pathLower + "|" + $hash.ToUpperInvariant()

                    if ($whitelistEntries.ContainsKey($key)) {

                        # Approved by you: path and hash match
                        $status = "Whitelist"
                    }
                    elseif ($whitelistPaths.ContainsKey($pathLower)) {

                        # Same path but different file: warning
                        $note = "Path is in the whitelist but the file has changed (different hash)"
                    }
                }
            }
        }

        # ----------------------------------------------------
        # Save to cache
        # ----------------------------------------------------

        $processCache[$processId] = [PSCustomObject]@{
            Process   = $processName
            Path      = $path
            Company   = $company
            Version   = $version
            Signature = $signature
            Publisher = $publisher
            Status    = $status
            Hash      = $hash
            Note      = $note
        }
    }

    # Retrieve process data
    $info = $processCache[$processId]

    # --------------------------------------------------------
    # Build the result row
    # --------------------------------------------------------

    [PSCustomObject]@{
        PID         = $processId
        Process     = $info.Process
        Remote_IP   = $conn.RemoteAddress
        Remote_Port = $conn.RemotePort
        Local_Port  = $conn.LocalPort
        Status      = $info.Status
        Signature   = $info.Signature
        Publisher   = $info.Publisher
        Company     = $info.Company
        Version     = $info.Version
        Hash        = $info.Hash
        Note        = $info.Note
        Path        = $info.Path
    }
}

# ------------------------------------------------------------
# REMOVE DUPLICATES
# (same PID to the same IP and port = a single row;
#  processes with different PIDs stay separate)
# ------------------------------------------------------------

$finalTable = @(
    $results |
    Sort-Object Process, Remote_IP, Remote_Port, PID -Unique
)

# ------------------------------------------------------------
# DISPLAY
# ------------------------------------------------------------

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "                 ANALYSIS RESULT" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

$finalTable |
    Format-Table `
        PID,
        Process,
        Remote_IP,
        Remote_Port,
        Local_Port,
        Status,
        Signature `
        -AutoSize

Write-Host ""
Write-Host "------------------------------------------------------------"

# ------------------------------------------------------------
# FIND ITEMS TO REVIEW
# ------------------------------------------------------------

$suspiciousItems = @(
    $finalTable |
    Where-Object {
        $_.Status -like "SUSPICIOUS*"
    }
)

$toCheckItems = @(
    $finalTable |
    Where-Object {
        $_.Status -like "TO CHECK*"
    }
)

$unverifiableItems = @(
    $finalTable |
    Where-Object {
        $_.Status -eq "UNVERIFIABLE"
    }
)

$whitelistedItems = @(
    $finalTable |
    Where-Object {
        $_.Status -eq "Whitelist"
    }
)

# ------------------------------------------------------------
# VERDICT
# ------------------------------------------------------------

Write-Host ""

if ($suspiciousItems.Count -gt 0) {

    Write-Host "[WARNING] Suspicious connections: $($suspiciousItems.Count)" -ForegroundColor Red
}
elseif (
    ($toCheckItems.Count -gt 0) -or
    ($unverifiableItems.Count -gt 0)
) {

    Write-Host "[INFO] No suspicious connection, but some items need review." -ForegroundColor Yellow
}
else {

    Write-Host "[OK] All analyzed connections look normal." -ForegroundColor Green
}

if ($toCheckItems.Count -gt 0) {
    Write-Host "  - To check        : $($toCheckItems.Count)" -ForegroundColor Yellow
}

if ($unverifiableItems.Count -gt 0) {
    Write-Host "  - Unverifiable    : $($unverifiableItems.Count)" -ForegroundColor Yellow

    if (-not $isAdmin) {
        Write-Host "    (run again as administrator to read their path)" -ForegroundColor Yellow
    }
}

if ($whitelistedItems.Count -gt 0) {
    Write-Host "  - Whitelisted     : $($whitelistedItems.Count)" -ForegroundColor DarkGray
}

# ------------------------------------------------------------
# DETAILS OF NON-"NORMAL" ITEMS
# (one block per process, with path, publisher and hash)
# ------------------------------------------------------------

$needsReview = @(
    $finalTable |
    Where-Object {
        ($_.Status -notlike "Normal*") -and
        ($_.Status -ne "Whitelist")
    }
)

if ($needsReview.Count -gt 0) {

    Write-Host ""
    Write-Host "------------------------------------------------------------"
    Write-Host "DETAILS OF ITEMS TO REVIEW (one block per process)" -ForegroundColor Cyan
    Write-Host "------------------------------------------------------------"

    $needsReview |
        Sort-Object PID -Unique |
        Format-List `
            PID,
            Process,
            Status,
            Signature,
            Publisher,
            Company,
            Version,
            Hash,
            Note,
            Path
}

# ------------------------------------------------------------
# SUMMARY
# ------------------------------------------------------------

Write-Host ""
Write-Host "External TCP connections found : $totalConnections"
Write-Host "Rows after removing duplicates : $($finalTable.Count)"
Write-Host "Distinct processes             : $($processCache.Count)"
Write-Host ""

# ------------------------------------------------------------
# ACTIONS ON SUSPICIOUS PROCESSES
# ------------------------------------------------------------

if ($suspiciousItems.Count -gt 0) {

    # One item per process (the connections are listed in the
    # "To" line shown below)
    $suspiciousProcesses = @(
        $suspiciousItems |
        Sort-Object PID -Unique
    )

    Write-Host "============================================================" -ForegroundColor Red
    Write-Host " SUSPICIOUS PROCESSES DETECTED: $($suspiciousProcesses.Count)" -ForegroundColor Red
    Write-Host "============================================================" -ForegroundColor Red
    Write-Host ""

    foreach ($p in $suspiciousProcesses) {

        $destinations = @(
            $suspiciousItems |
            Where-Object { $_.PID -eq $p.PID } |
            ForEach-Object { "$($_.Remote_IP):$($_.Remote_Port)" }
        )

        Write-Host ("  PID {0} - {1}" -f $p.PID, $p.Process) -ForegroundColor Red
        Write-Host ("     Path : {0}" -f $p.Path)
        Write-Host ("     To   : {0}" -f ($destinations -join ", "))
        Write-Host ""
    }

    $terminate = Read-YesNo "Terminate ALL the listed suspicious processes (this also closes their connections)?"

    Write-Host ""

    # --------------------------------------------------------
    # ANSWER YES: terminate the processes
    # --------------------------------------------------------

    if ($terminate) {

        $terminated = @()

        foreach ($p in $suspiciousProcesses) {

            $procId = $p.PID
            $label = "PID $procId - $($p.Process)"

            # Safeguard 1: never terminate this script, nor PID 0 and 4
            if (($procId -eq $PID) -or (@(0, 4) -contains $procId)) {
                Write-Host "[SKIPPED] $label : protected process." -ForegroundColor Yellow
                continue
            }

            # Safeguard 2: never terminate critical system processes
            $sys32 = ($env:windir + "\system32\").ToLowerInvariant()

            if (
                ($criticalProcesses -contains $p.Process) -and
                $p.Path.ToLowerInvariant().StartsWith($sys32)
            ) {
                Write-Host "[SKIPPED] $label : critical system process." -ForegroundColor Yellow
                continue
            }

            # Safeguard 3: time has passed between the analysis and
            # your answer. Check that this PID is still the same
            # program (a PID can be reassigned to another one).
            $currentCim = Get-CimInstance `
                Win32_Process `
                -Filter "ProcessId=$procId" `
                -ErrorAction SilentlyContinue

            if (-not $currentCim) {
                Write-Host "[ALREADY ENDED] $label" -ForegroundColor DarkGray
                continue
            }

            if (
                (-not $currentCim.ExecutablePath) -or
                ($currentCim.ExecutablePath -ne $p.Path)
            ) {
                Write-Host "[SKIPPED] $label : this PID now belongs to a different program." -ForegroundColor Yellow
                continue
            }

            # Terminate the process
            try {

                Stop-Process -Id $procId -Force -ErrorAction Stop

                Start-Sleep -Milliseconds 400

                if (Get-Process -Id $procId -ErrorAction SilentlyContinue) {
                    Write-Host "[ERROR] $label : still running." -ForegroundColor Red
                }
                else {
                    Write-Host "[TERMINATED] $label" -ForegroundColor Green
                    $terminated += $p
                }

            }
            catch {
                Write-Host "[ERROR] $label : $($_.Exception.Message)" -ForegroundColor Red
            }
        }

        Write-Host ""
        Write-Host "Processes terminated: $($terminated.Count) of $($suspiciousProcesses.Count)" -ForegroundColor Cyan

        # ----------------------------------------------------
        # Optional quarantine of the files (deletes nothing)
        # ----------------------------------------------------

        if ($terminated.Count -gt 0) {

            Write-Host ""
            Write-Host "The files of the terminated programs are still on disk and" -ForegroundColor Yellow
            Write-Host "could start again (autostart, scheduled tasks)." -ForegroundColor Yellow
            Write-Host "You can move them to the Quarantine folder: they are not" -ForegroundColor Yellow
            Write-Host "deleted and you can restore them by hand at any time." -ForegroundColor Yellow
            Write-Host ""

            $quarantine = Read-YesNo "Move the files of the terminated programs to quarantine?"

            Write-Host ""

            if ($quarantine) {

                $filesToMove = @(
                    $terminated |
                    Sort-Object Path -Unique
                )

                if (-not (Test-Path -LiteralPath $quarantineFolder)) {
                    New-Item `
                        -ItemType Directory `
                        -Path $quarantineFolder `
                        -Force |
                        Out-Null
                }

                foreach ($f in $filesToMove) {

                    $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
                    $fileName = [System.IO.Path]::GetFileName($f.Path)

                    # .quarantine extension: the file is no longer executable
                    $destination = Join-Path `
                        $quarantineFolder `
                        ($stamp + "_" + $fileName + ".quarantine")

                    try {

                        Move-Item `
                            -LiteralPath $f.Path `
                            -Destination $destination `
                            -Force `
                            -ErrorAction Stop

                        # Index used to restore: new name | original path
                        Add-Content `
                            -LiteralPath $quarantineIndexFile `
                            -Value ("{0}|{1}" -f $destination, $f.Path) `
                            -Encoding UTF8

                        Write-Host "[QUARANTINED] $fileName" -ForegroundColor Green
                    }
                    catch {
                        Write-Host "[ERROR] $fileName : $($_.Exception.Message)" -ForegroundColor Red
                    }
                }

                Write-Host ""
                Write-Host "Quarantine folder: $quarantineFolder" -ForegroundColor Cyan
                Write-Host "To restore a file: see quarantine.txt (new name | original path)." -ForegroundColor Cyan
            }
        }
    }

    # --------------------------------------------------------
    # ANSWER NO: offer the whitelist, one process at a time
    # --------------------------------------------------------

    else {

        Write-Host "No process terminated." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "You can approve the processes you trust: they will be saved in" -ForegroundColor Cyan
        Write-Host "whitelist.txt (path + hash) and will no longer be flagged," -ForegroundColor Cyan
        Write-Host "as long as the file stays identical." -ForegroundColor Cyan
        Write-Host ""

        $added = 0

        foreach ($p in $suspiciousProcesses) {

            if ($p.Hash -eq "N/A") {
                Write-Host "[SKIPPED] $($p.Process) : cannot compute the file hash." -ForegroundColor Yellow
                continue
            }

            Write-Host ("Process : {0}" -f $p.Process)
            Write-Host ("Path    : {0}" -f $p.Path)

            $approve = Read-YesNo "Add to the whitelist?"

            if ($approve) {

                Add-WhitelistEntry `
                    -Hash $p.Hash `
                    -FilePath $p.Path `
                    -ProcessName $p.Process

                $added++

                Write-Host "[WHITELIST] Added: $($p.Process)" -ForegroundColor Green
            }
            else {
                Write-Host "Not added: it will be flagged again next time." -ForegroundColor DarkGray
            }

            Write-Host ""
        }

        if ($added -gt 0) {
            Write-Host "Entries added to whitelist.txt: $added" -ForegroundColor Cyan
            Write-Host "File: $whitelistFile" -ForegroundColor Cyan
        }
    }

    Write-Host ""
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Analysis complete." -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
