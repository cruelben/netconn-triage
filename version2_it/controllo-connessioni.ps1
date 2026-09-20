# ============================================================
# CONTROLLO CONNESSIONI TCP E PROCESSI  (versione 3)
# ============================================================
# Elenca le connessioni TCP ESTABLISHED verso IP esterni e, per
# ogni processo coinvolto, controlla percorso e firma digitale.
#
# Esiti possibili:
#   Normale           - firma valida e percorso ordinario
#   Whitelist         - processo che hai approvato tu (whitelist.txt)
#   DA VERIFICARE     - firma non valida oppure percorso insolito
#   SOSPETTO          - percorso insolito E firma non valida
#   NON VERIFICABILE  - percorso del programma non leggibile
#                       (spesso serve avviare come amministratore)
#
# Se trova processi SOSPETTI ti chiede:
#   1) Terminarli tutti? (chiude anche le loro connessioni)
#        SI  -> termina i processi; poi puoi spostare i loro file
#               in quarantena (NON vengono cancellati)
#        NO  -> per ogni processo chiede se aggiungerlo alla
#               whitelist (whitelist.txt, nella cartella dello script)
#
# La whitelist salva PERCORSO + HASH SHA256 del file: se il file
# viene sostituito o modificato, torna ad essere segnalato.
#
# LIMITI: e' una fotografia del momento. Non vede le connessioni
# UDP (es. QUIC/HTTP3 dei browser) ne' quelle molto brevi.
# Un programma firmato o iniettato in un processo legittimo
# risulterebbe comunque "Normale".
# ============================================================

# ------------------------------------------------------------
# CONFIGURAZIONE
# ------------------------------------------------------------

# Editori di cui ti fidi. Se un programma in \AppData\ ha una
# firma VALIDA di uno di questi editori, viene considerato Normale
# (evita i falsi positivi di Discord, Spotify, Chrome, ecc.).
# Il nome esatto lo vedi nella colonna "Editore" del dettaglio.
$editoriFidati = @(
    "Microsoft Corporation",
    "Google LLC",
    "Mozilla Corporation",
    "Discord Inc.",
    "Spotify AB",
    "Telegram FZ-LLC"
)

# Processi di sistema protetti il cui percorso non e' leggibile
# nemmeno da amministratore. Vengono considerati Normali SOLO se
# lo script e' avviato come amministratore.
$processiProtettiNoti = @(
    "MpDefenderCoreService"
)

# Processi che non vengono MAI terminati dalla funzione di pulizia
# (se si trovano in System32)
$processiCritici = @(
    "system", "idle", "registry", "smss", "csrss", "wininit",
    "winlogon", "services", "lsass", "svchost", "explorer",
    "dwm", "fontdrvhost", "lsm"
)

# Cartella dello script: qui vengono salvati whitelist.txt e la
# cartella Quarantena
$cartellaScript = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($cartellaScript)) {
    $cartellaScript = (Get-Location).Path
}

$fileWhitelist = Join-Path $cartellaScript "whitelist.txt"
$cartellaQuarantena = Join-Path $cartellaScript "Quarantena"
$fileIndiceQuarantena = Join-Path $cartellaQuarantena "quarantena.txt"

Clear-Host

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "   ANALISI CONNESSIONI TCP E PROCESSI" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# ------------------------------------------------------------
# CONTROLLO PRIVILEGI DI AMMINISTRATORE
# ------------------------------------------------------------
# Senza privilegi elevati, il percorso di molti processi di sistema
# non e' leggibile e non si possono terminare processi elevati.

$identita = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identita)
$eAmministratore = $principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

if (-not $eAmministratore) {
    Write-Host "[!] Script NON avviato come amministratore." -ForegroundColor Yellow
    Write-Host "    Alcuni processi risulteranno 'NON VERIFICABILE' e" -ForegroundColor Yellow
    Write-Host "    non potrai terminare quelli avviati con privilegi elevati." -ForegroundColor Yellow
    Write-Host "    Per un'analisi completa: tasto destro su run.bat" -ForegroundColor Yellow
    Write-Host "    > Esegui come amministratore." -ForegroundColor Yellow
    Write-Host ""
}

# ------------------------------------------------------------
# FUNZIONE: verifica se un IP e' locale, privato o multicast
# ------------------------------------------------------------
function Test-IPPrivatoLocale {

    param (
        [string]$IP
    )

    try {
        $address = [System.Net.IPAddress]::Parse($IP)
    }
    catch {
        return $false
    }

    # IPv4 scritto in formato IPv6 (::ffff:a.b.c.d):
    # lo converto in IPv4 normale prima di controllarlo
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

        # 0.0.0.0/8 (indirizzo non specificato)
        if ($b[0] -eq 0) {
            return $true
        }

        # 10.0.0.0/8
        if ($b[0] -eq 10) {
            return $true
        }

        # 100.64.0.0/10 (CGNAT, usato ad es. da Tailscale)
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

        # 224.0.0.0/4 multicast (e oltre: riservati/broadcast)
        if ($b[0] -ge 224) {
            return $true
        }
    }

    # --------------------------------------------------------
    # IPv6
    # --------------------------------------------------------
    else {

        $b = $address.GetAddressBytes()

        # :: (indirizzo non specificato)
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
# FUNZIONE: domanda SI/NO (ripete finche' la risposta e' valida)
# ------------------------------------------------------------
function Chiedi-SiNo {

    param (
        [string]$Domanda
    )

    while ($true) {

        $risposta = Read-Host "$Domanda (S/N)"

        if ($null -eq $risposta) {
            return $false
        }

        $risposta = $risposta.Trim().ToLowerInvariant()

        if (@("s", "si", "y", "yes") -contains $risposta) {
            return $true
        }

        if (@("n", "no") -contains $risposta) {
            return $false
        }

        Write-Host "Risposta non valida: scrivi S oppure N." -ForegroundColor Yellow
    }
}

# ------------------------------------------------------------
# FUNZIONE: aggiunge una voce a whitelist.txt
# Formato riga: SHA256|Percorso|Processo|DataInserimento
# ------------------------------------------------------------
function Add-Whitelist {

    param (
        [string]$Hash,
        [string]$Percorso,
        [string]$Processo
    )

    # Se il file non esiste lo creo con una breve intestazione
    if (-not (Test-Path -LiteralPath $fileWhitelist)) {

        $intestazione = @(
            "# WHITELIST di controllo-connessioni.ps1",
            "# Formato: SHA256|Percorso|Processo|DataInserimento",
            "# Un processo e' approvato solo se percorso E hash coincidono.",
            "# Per rimuovere una voce basta cancellare la sua riga."
        )

        Set-Content `
            -LiteralPath $fileWhitelist `
            -Value $intestazione `
            -Encoding UTF8
    }

    $riga = "{0}|{1}|{2}|{3}" -f `
        $Hash.ToUpperInvariant(),
        $Percorso,
        $Processo,
        (Get-Date -Format "yyyy-MM-dd HH:mm")

    Add-Content `
        -LiteralPath $fileWhitelist `
        -Value $riga `
        -Encoding UTF8
}

# ------------------------------------------------------------
# CARICA LA WHITELIST (se esiste)
# ------------------------------------------------------------
# $whitelistVoci     : chiave "percorso|HASH" -> approvato
# $whitelistPercorsi : percorsi gia' presenti (con qualunque hash),
#                      serve a segnalare i file modificati

$whitelistVoci = @{}
$whitelistPercorsi = @{}

if (Test-Path -LiteralPath $fileWhitelist) {

    $righeWhitelist = Get-Content `
        -LiteralPath $fileWhitelist `
        -Encoding UTF8 `
        -ErrorAction SilentlyContinue

    foreach ($riga in $righeWhitelist) {

        $riga = $riga.Trim()

        # Salto righe vuote e commenti
        if (($riga -eq "") -or $riga.StartsWith("#")) {
            continue
        }

        $parti = $riga.Split("|")

        if ($parti.Count -lt 2) {
            continue
        }

        $hashVoce = $parti[0].Trim().ToUpperInvariant()
        $percorsoVoce = $parti[1].Trim().ToLowerInvariant()

        $whitelistVoci[$percorsoVoce + "|" + $hashVoce] = $true
        $whitelistPercorsi[$percorsoVoce] = $true
    }

    Write-Host "Whitelist caricata: $($whitelistVoci.Count) voce/i." -ForegroundColor DarkGray
}

Write-Host "Analisi delle connessioni in corso..." -ForegroundColor Yellow
Write-Host ""

# ------------------------------------------------------------
# OTTIENI CONNESSIONI TCP ESTABLISHED VERSO IP ESTERNI
# ------------------------------------------------------------

$connessioni = @(
    Get-NetTCPConnection `
        -State Established `
        -ErrorAction SilentlyContinue |
    Where-Object {
        -not (Test-IPPrivatoLocale $_.RemoteAddress)
    }
)

# ------------------------------------------------------------
# NESSUNA CONNESSIONE
# ------------------------------------------------------------

if ($connessioni.Count -eq 0) {

    Write-Host "[OK] Nessuna connessione TCP esterna attiva trovata." -ForegroundColor Green
    Write-Host ""
    Write-Host "Analisi completata." -ForegroundColor Yellow

    return
}

$totaleConnessioni = $connessioni.Count

Write-Host "Trovate $totaleConnessioni connessioni TCP esterne." -ForegroundColor Green
Write-Host ""

# ------------------------------------------------------------
# CACHE DEI PROCESSI
# (ogni processo viene analizzato una sola volta)
# ------------------------------------------------------------

$processCache = @{}

# ------------------------------------------------------------
# ANALISI DELLE CONNESSIONI
# ------------------------------------------------------------

$risultato = foreach ($conn in $connessioni) {

    # IMPORTANTE:
    # Non usare $pid: e' una variabile automatica di PowerShell.
    $processId = $conn.OwningProcess

    # --------------------------------------------------------
    # Recupera informazioni processo (solo se non gia' in cache)
    # --------------------------------------------------------

    if (-not $processCache.ContainsKey($processId)) {

        $processo = Get-Process `
            -Id $processId `
            -ErrorAction SilentlyContinue

        $cimProcesso = Get-CimInstance `
            Win32_Process `
            -Filter "ProcessId=$processId" `
            -ErrorAction SilentlyContinue

        # Nome processo
        if ($processo) {
            $nomeProcesso = $processo.Name
        }
        else {
            $nomeProcesso = "N/D"
        }

        # ----------------------------------------------------
        # Percorso eseguibile
        # ----------------------------------------------------

        $path = $null

        if ($cimProcesso -and $cimProcesso.ExecutablePath) {
            $path = $cimProcesso.ExecutablePath
        }
        elseif ($processo -and $processo.Path) {
            $path = $processo.Path
        }

        if ([string]::IsNullOrWhiteSpace($path)) {
            $path = "N/D"
        }

        # Il file esiste ed e' leggibile?
        # (-LiteralPath: gestisce anche percorsi con [ ] nel nome)
        $fileEsiste = ($path -ne "N/D") -and (Test-Path -LiteralPath $path)

        # ----------------------------------------------------
        # Informazioni file (azienda e versione)
        # ----------------------------------------------------

        $azienda = "N/D"
        $versione = "N/D"

        if ($fileEsiste) {

            try {

                $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($path)

                if ($versionInfo.CompanyName) {
                    $azienda = $versionInfo.CompanyName
                }

                if ($versionInfo.FileVersion) {
                    $versione = $versionInfo.FileVersion
                }

            }
            catch {
                # Ignoro: restano "N/D"
            }
        }

        # ----------------------------------------------------
        # Firma digitale
        # ----------------------------------------------------

        $firma = "N/D"
        $editore = "N/D"

        if ($fileEsiste) {

            try {

                $firmaInfo = Get-AuthenticodeSignature `
                    -LiteralPath $path `
                    -ErrorAction SilentlyContinue

                if ($firmaInfo) {

                    $firma = switch ($firmaInfo.Status) {

                        "Valid"        { "Valida" }
                        "NotSigned"    { "Non firmato" }
                        "NotTrusted"   { "Non attendibile" }
                        "HashMismatch" { "Hash non valido" }

                        # Qualsiasi altro stato (es. UnknownError):
                        # NON lo considero valido
                        default {
                            "Altro (" + [string]$firmaInfo.Status + ")"
                        }
                    }

                    if ($firmaInfo.SignerCertificate) {

                        try {

                            $editore =
                                $firmaInfo.SignerCertificate.GetNameInfo(
                                    [System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName,
                                    $false
                                )

                        }
                        catch {
                            $editore = "N/D"
                        }
                    }
                }

            }
            catch {
                $firma = "N/D"
            }
        }

        # ----------------------------------------------------
        # Valutazione
        # ----------------------------------------------------

        $stato = "Normale"
        $hash = "N/D"
        $nota = ""

        if ($path -eq "N/D") {

            # Percorso illeggibile. Se sono amministratore ed e' un
            # processo protetto noto (es. Defender) lo considero Normale,
            # altrimenti non posso giudicare.
            if (
                $eAmministratore -and
                ($processiProtettiNoti -contains $nomeProcesso)
            ) {
                $stato = "Normale (processo protetto)"
            }
            else {
                $stato = "NON VERIFICABILE"
            }
        }
        else {

            $percorsoLower = $path.ToLowerInvariant()
            $firmaValida = ($firma -eq "Valida")

            # Cartelle molto insolite per un programma
            $inTempDownloads = (
                $percorsoLower -like "*\temp\*" -or
                $percorsoLower -like "*\downloads\*"
            )

            # AppData: usata anche da molte app legittime
            $inAppData = ($percorsoLower -like "*\appdata\*")

            # Editore presente nella lista di fiducia?
            $editoreFidato = ($editoriFidati -contains $editore)

            if ($inTempDownloads) {

                if ($firmaValida) {
                    $stato = "DA VERIFICARE (percorso)"
                }
                else {
                    $stato = "SOSPETTO (percorso/firma)"
                }

            }
            elseif ($inAppData) {

                if ($firmaValida -and $editoreFidato) {
                    $stato = "Normale"
                }
                elseif ($firmaValida) {
                    $stato = "DA VERIFICARE (percorso)"
                }
                else {
                    $stato = "SOSPETTO (percorso/firma)"
                }

            }
            elseif (-not $firmaValida) {

                # Percorso normale ma firma assente o non valida
                $stato = "DA VERIFICARE (firma)"
            }
            else {

                $stato = "Normale"
            }

            # ------------------------------------------------
            # Se il processo NON e' "Normale", calcolo l'hash del
            # file e controllo la whitelist (percorso + hash)
            # ------------------------------------------------

            if ($stato -ne "Normale") {

                if ($fileEsiste) {

                    try {
                        $hash = (
                            Get-FileHash `
                                -LiteralPath $path `
                                -Algorithm SHA256 `
                                -ErrorAction Stop
                        ).Hash
                    }
                    catch {
                        $hash = "N/D"
                    }
                }

                if ($hash -ne "N/D") {

                    $chiave = $percorsoLower + "|" + $hash.ToUpperInvariant()

                    if ($whitelistVoci.ContainsKey($chiave)) {

                        # Approvato da te: percorso e hash coincidono
                        $stato = "Whitelist"
                    }
                    elseif ($whitelistPercorsi.ContainsKey($percorsoLower)) {

                        # Stesso percorso ma file diverso: attenzione
                        $nota = "Percorso in whitelist ma il file e' cambiato (hash diverso)"
                    }
                }
            }
        }

        # ----------------------------------------------------
        # Salva nella cache
        # ----------------------------------------------------

        $processCache[$processId] = [PSCustomObject]@{
            Processo = $nomeProcesso
            Percorso = $path
            Azienda  = $azienda
            Versione = $versione
            Firma    = $firma
            Editore  = $editore
            Esito    = $stato
            Hash     = $hash
            Nota     = $nota
        }
    }

    # Recupera dati del processo
    $info = $processCache[$processId]

    # --------------------------------------------------------
    # Costruisce riga risultato
    # --------------------------------------------------------

    [PSCustomObject]@{
        PID          = $processId
        Processo     = $info.Processo
        IP_Remoto    = $conn.RemoteAddress
        Porta_Remota = $conn.RemotePort
        Porta_Locale = $conn.LocalPort
        Esito        = $info.Esito
        Firma        = $info.Firma
        Editore      = $info.Editore
        Azienda      = $info.Azienda
        Versione     = $info.Versione
        Hash         = $info.Hash
        Nota         = $info.Nota
        Percorso     = $info.Percorso
    }
}

# ------------------------------------------------------------
# RIMUOVE DUPLICATI
# (stesso PID verso stesso IP e porta = una sola riga;
#  processi con PID diverso restano separati)
# ------------------------------------------------------------

$tabellaFinale = @(
    $risultato |
    Sort-Object Processo, IP_Remoto, Porta_Remota, PID -Unique
)

# ------------------------------------------------------------
# VISUALIZZAZIONE
# ------------------------------------------------------------

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "                 RISULTATO ANALISI" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

$tabellaFinale |
    Format-Table `
        PID,
        Processo,
        IP_Remoto,
        Porta_Remota,
        Porta_Locale,
        Esito,
        Firma `
        -AutoSize

Write-Host ""
Write-Host "------------------------------------------------------------"

# ------------------------------------------------------------
# RICERCA ELEMENTI DA CONTROLLARE
# ------------------------------------------------------------

$elementiSospetti = @(
    $tabellaFinale |
    Where-Object {
        $_.Esito -like "SOSPETTO*"
    }
)

$elementiDaVerificare = @(
    $tabellaFinale |
    Where-Object {
        $_.Esito -like "DA VERIFICARE*"
    }
)

$elementiNonVerificabili = @(
    $tabellaFinale |
    Where-Object {
        $_.Esito -eq "NON VERIFICABILE"
    }
)

$elementiWhitelist = @(
    $tabellaFinale |
    Where-Object {
        $_.Esito -eq "Whitelist"
    }
)

# ------------------------------------------------------------
# VERDETTO
# ------------------------------------------------------------

Write-Host ""

if ($elementiSospetti.Count -gt 0) {

    Write-Host "[ATTENZIONE] Connessioni sospette: $($elementiSospetti.Count)" -ForegroundColor Red
}
elseif (
    ($elementiDaVerificare.Count -gt 0) -or
    ($elementiNonVerificabili.Count -gt 0)
) {

    Write-Host "[INFO] Nessuna connessione sospetta, ma ci sono elementi da controllare." -ForegroundColor Yellow
}
else {

    Write-Host "[OK] Tutte le connessioni analizzate risultano normali." -ForegroundColor Green
}

if ($elementiDaVerificare.Count -gt 0) {
    Write-Host "  - Da verificare      : $($elementiDaVerificare.Count)" -ForegroundColor Yellow
}

if ($elementiNonVerificabili.Count -gt 0) {
    Write-Host "  - Non verificabili   : $($elementiNonVerificabili.Count)" -ForegroundColor Yellow

    if (-not $eAmministratore) {
        Write-Host "    (riprova come amministratore per leggerne il percorso)" -ForegroundColor Yellow
    }
}

if ($elementiWhitelist.Count -gt 0) {
    Write-Host "  - In whitelist       : $($elementiWhitelist.Count)" -ForegroundColor DarkGray
}

# ------------------------------------------------------------
# DETTAGLIO DEGLI ELEMENTI NON "NORMALI"
# (un blocco per processo, con percorso, editore e hash)
# ------------------------------------------------------------

$daControllare = @(
    $tabellaFinale |
    Where-Object {
        ($_.Esito -notlike "Normale*") -and
        ($_.Esito -ne "Whitelist")
    }
)

if ($daControllare.Count -gt 0) {

    Write-Host ""
    Write-Host "------------------------------------------------------------"
    Write-Host "DETTAGLIO ELEMENTI DA CONTROLLARE (un blocco per processo)" -ForegroundColor Cyan
    Write-Host "------------------------------------------------------------"

    $daControllare |
        Sort-Object PID -Unique |
        Format-List `
            PID,
            Processo,
            Esito,
            Firma,
            Editore,
            Azienda,
            Versione,
            Hash,
            Nota,
            Percorso
}

# ------------------------------------------------------------
# RIEPILOGO
# ------------------------------------------------------------

Write-Host ""
Write-Host "Connessioni TCP esterne trovate : $totaleConnessioni"
Write-Host "Righe dopo rimozione duplicati  : $($tabellaFinale.Count)"
Write-Host "Processi distinti               : $($processCache.Count)"
Write-Host ""

# ------------------------------------------------------------
# AZIONI SUI PROCESSI SOSPETTI
# ------------------------------------------------------------

if ($elementiSospetti.Count -gt 0) {

    # Un elemento per processo (le connessioni stanno nella colonna
    # "destinazioni" mostrata qui sotto)
    $processiSospetti = @(
        $elementiSospetti |
        Sort-Object PID -Unique
    )

    Write-Host "============================================================" -ForegroundColor Red
    Write-Host " PROCESSI SOSPETTI RILEVATI: $($processiSospetti.Count)" -ForegroundColor Red
    Write-Host "============================================================" -ForegroundColor Red
    Write-Host ""

    foreach ($p in $processiSospetti) {

        $destinazioni = @(
            $elementiSospetti |
            Where-Object { $_.PID -eq $p.PID } |
            ForEach-Object { "$($_.IP_Remoto):$($_.Porta_Remota)" }
        )

        Write-Host ("  PID {0} - {1}" -f $p.PID, $p.Processo) -ForegroundColor Red
        Write-Host ("     Percorso : {0}" -f $p.Percorso)
        Write-Host ("     Verso    : {0}" -f ($destinazioni -join ", "))
        Write-Host ""
    }

    $terminare = Chiedi-SiNo "Terminare TUTTI i processi sospetti elencati (chiude anche le loro connessioni)?"

    Write-Host ""

    # --------------------------------------------------------
    # RISPOSTA SI: termina i processi
    # --------------------------------------------------------

    if ($terminare) {

        $terminati = @()

        foreach ($p in $processiSospetti) {

            $idProc = $p.PID
            $etichetta = "PID $idProc - $($p.Processo)"

            # Protezione 1: mai terminare questo script, ne' PID 0 e 4
            if (($idProc -eq $PID) -or (@(0, 4) -contains $idProc)) {
                Write-Host "[SALTATO] $etichetta : processo protetto." -ForegroundColor Yellow
                continue
            }

            # Protezione 2: mai terminare processi critici di sistema
            $sys32 = ($env:windir + "\system32\").ToLowerInvariant()

            if (
                ($processiCritici -contains $p.Processo) -and
                $p.Percorso.ToLowerInvariant().StartsWith($sys32)
            ) {
                Write-Host "[SALTATO] $etichetta : processo critico di sistema." -ForegroundColor Yellow
                continue
            }

            # Protezione 3: tra l'analisi e la tua risposta e' passato
            # del tempo. Verifico che quel PID sia ancora lo stesso
            # programma (un PID puo' essere riassegnato ad altri).
            $cimAttuale = Get-CimInstance `
                Win32_Process `
                -Filter "ProcessId=$idProc" `
                -ErrorAction SilentlyContinue

            if (-not $cimAttuale) {
                Write-Host "[GIA' TERMINATO] $etichetta" -ForegroundColor DarkGray
                continue
            }

            if (
                (-not $cimAttuale.ExecutablePath) -or
                ($cimAttuale.ExecutablePath -ne $p.Percorso)
            ) {
                Write-Host "[SALTATO] $etichetta : il PID ora corrisponde a un altro programma." -ForegroundColor Yellow
                continue
            }

            # Termina il processo
            try {

                Stop-Process -Id $idProc -Force -ErrorAction Stop

                Start-Sleep -Milliseconds 400

                if (Get-Process -Id $idProc -ErrorAction SilentlyContinue) {
                    Write-Host "[ERRORE] $etichetta : e' ancora attivo." -ForegroundColor Red
                }
                else {
                    Write-Host "[TERMINATO] $etichetta" -ForegroundColor Green
                    $terminati += $p
                }

            }
            catch {
                Write-Host "[ERRORE] $etichetta : $($_.Exception.Message)" -ForegroundColor Red
            }
        }

        Write-Host ""
        Write-Host "Processi terminati: $($terminati.Count) su $($processiSospetti.Count)" -ForegroundColor Cyan

        # ----------------------------------------------------
        # Quarantena opzionale dei file (NON cancella nulla)
        # ----------------------------------------------------

        if ($terminati.Count -gt 0) {

            Write-Host ""
            Write-Host "I file dei programmi terminati sono ancora sul disco e" -ForegroundColor Yellow
            Write-Host "potrebbero riavviarsi (avvio automatico, attivita' pianificate)." -ForegroundColor Yellow
            Write-Host "Puoi spostarli nella cartella Quarantena: non vengono" -ForegroundColor Yellow
            Write-Host "cancellati e li puoi ripristinare a mano in qualsiasi momento." -ForegroundColor Yellow
            Write-Host ""

            $quarantena = Chiedi-SiNo "Spostare in quarantena i file dei programmi terminati?"

            Write-Host ""

            if ($quarantena) {

                $fileDaSpostare = @(
                    $terminati |
                    Sort-Object Percorso -Unique
                )

                if (-not (Test-Path -LiteralPath $cartellaQuarantena)) {
                    New-Item `
                        -ItemType Directory `
                        -Path $cartellaQuarantena `
                        -Force |
                        Out-Null
                }

                foreach ($f in $fileDaSpostare) {

                    $marca = Get-Date -Format "yyyyMMdd_HHmmss"
                    $nomeFile = [System.IO.Path]::GetFileName($f.Percorso)

                    # Estensione .quarantena: il file non e' piu' eseguibile
                    $destinazione = Join-Path `
                        $cartellaQuarantena `
                        ($marca + "_" + $nomeFile + ".quarantena")

                    try {

                        Move-Item `
                            -LiteralPath $f.Percorso `
                            -Destination $destinazione `
                            -Force `
                            -ErrorAction Stop

                        # Indice per ripristinare: nuovo nome | percorso originale
                        Add-Content `
                            -LiteralPath $fileIndiceQuarantena `
                            -Value ("{0}|{1}" -f $destinazione, $f.Percorso) `
                            -Encoding UTF8

                        Write-Host "[QUARANTENA] $nomeFile" -ForegroundColor Green
                    }
                    catch {
                        Write-Host "[ERRORE] $nomeFile : $($_.Exception.Message)" -ForegroundColor Red
                    }
                }

                Write-Host ""
                Write-Host "Cartella quarantena: $cartellaQuarantena" -ForegroundColor Cyan
                Write-Host "Per ripristinare un file: vedi quarantena.txt (nuovo nome | percorso originale)." -ForegroundColor Cyan
            }
        }
    }

    # --------------------------------------------------------
    # RISPOSTA NO: propone la whitelist, un processo alla volta
    # --------------------------------------------------------

    else {

        Write-Host "Nessun processo terminato." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Puoi approvare i processi di cui ti fidi: verranno salvati in" -ForegroundColor Cyan
        Write-Host "whitelist.txt (percorso + hash) e non saranno piu' segnalati," -ForegroundColor Cyan
        Write-Host "finche' il file resta identico." -ForegroundColor Cyan
        Write-Host ""

        $aggiunti = 0

        foreach ($p in $processiSospetti) {

            if ($p.Hash -eq "N/D") {
                Write-Host "[SALTATO] $($p.Processo) : non riesco a calcolare l'hash del file." -ForegroundColor Yellow
                continue
            }

            Write-Host ("Processo : {0}" -f $p.Processo)
            Write-Host ("Percorso : {0}" -f $p.Percorso)

            $approva = Chiedi-SiNo "Aggiungere alla whitelist?"

            if ($approva) {

                Add-Whitelist `
                    -Hash $p.Hash `
                    -Percorso $p.Percorso `
                    -Processo $p.Processo

                $aggiunti++

                Write-Host "[WHITELIST] Aggiunto: $($p.Processo)" -ForegroundColor Green
            }
            else {
                Write-Host "Non aggiunto: sara' ancora segnalato la prossima volta." -ForegroundColor DarkGray
            }

            Write-Host ""
        }

        if ($aggiunti -gt 0) {
            Write-Host "Voci aggiunte a whitelist.txt: $aggiunti" -ForegroundColor Cyan
            Write-Host "File: $fileWhitelist" -ForegroundColor Cyan
        }
    }

    Write-Host ""
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Analisi completata." -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan