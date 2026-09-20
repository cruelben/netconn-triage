# ============================================================
# FALSO POSITIVO - TEST INNOCUO PER controllo-connessioni.ps1
# ============================================================
# Cosa fa:
#   1. Compila un minuscolo programma NON FIRMATO in una sottocartella
#      "temp" dentro .\fake_process (cioe' accanto a questo script).
#      Il nome "temp" nel percorso, insieme alla firma assente, lo
#      rende "sospetto" per controllo-connessioni.ps1.
#   2. Lo avvia: il programma apre UNA connessione TCP verso un
#      sito di test pubblico e la mantiene aperta.
#   3. Aspetta che tu lanci run.bat e controlli il risultato.
#   4. Alla fine (INVIO, CTRL+C o tempo scaduto) ferma il programma
#      e cancella il file compilato.
#
# Cosa NON fa:
#   - non modifica il sistema, il registro o i tuoi file
#   - non scarica ne' invia dati tuoi: manda solo una richiesta
#     HTTP "HEAD /" ogni 5 secondi a $HostTest
#   - non resta in esecuzione: si ferma da solo dopo $DurataMaxSecondi
#
# Esito atteso in controllo-connessioni.ps1:
#   Processo: falso_positivo_test
#   Esito   : SOSPETTO (percorso/firma)
#
# NOTA: richiede Windows PowerShell 5.1 (quello avviato da
# falso_positivo.bat), non PowerShell 7.
# ============================================================

# ------------------------------------------------------------
# CONFIGURAZIONE
# ------------------------------------------------------------

# Sito di test: example.com e' un dominio riservato dallo IANA
# proprio per prove e documentazione.
$HostTest = "example.com"
$PortaTest = 80

# Durata massima del test (poi il programma si ferma da solo)
$DurataMaxSecondi = 300

# Cartella dello script (stessa di falso_positivo.bat)
$cartellaScript = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($cartellaScript)) {
    $cartellaScript = (Get-Location).Path
}

# Percorso del programma di test: .\fake_process\temp\
# ATTENZIONE: la sottocartella deve chiamarsi "temp" (o "downloads"):
# controllo-connessioni.ps1 considera SOSPETTO un programma non firmato
# solo se il percorso contiene \temp\, \downloads\ o \appdata\.
# In una cartella "normale" verrebbe classificato solo DA VERIFICARE.
$nomeExe = "falso_positivo_test.exe"
$cartellaFake = Join-Path $cartellaScript "fake_process"
$cartellaTest = Join-Path $cartellaFake "temp"
$exePath = Join-Path $cartellaTest $nomeExe

# ------------------------------------------------------------
# CODICE C# DEL PROGRAMMA DI TEST
# ------------------------------------------------------------
# Apre una connessione TCP, invia una richiesta HEAD ogni 5
# secondi per tenerla viva e, se il server la chiude, la riapre.
# Finito il tempo, esce.

$codiceCSharp = @'
using System;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Threading;

public static class FalsoPositivoTest
{
    public static int Main(string[] args)
    {
        string host = "example.com";
        int porta = 80;
        int secondi = 120;

        if (args.Length > 0) { host = args[0]; }
        if (args.Length > 1) { int.TryParse(args[1], out porta); }
        if (args.Length > 2) { int.TryParse(args[2], out secondi); }

        DateTime fine = DateTime.UtcNow.AddSeconds(secondi);

        byte[] richiesta = Encoding.ASCII.GetBytes(
            "HEAD / HTTP/1.1\r\nHost: " + host +
            "\r\nConnection: keep-alive\r\n\r\n");

        byte[] buffer = new byte[4096];
        TcpClient client = null;
        NetworkStream stream = null;

        while (DateTime.UtcNow < fine)
        {
            try
            {
                if (client == null)
                {
                    client = new TcpClient();
                    client.Connect(host, porta);
                    stream = client.GetStream();
                    stream.ReadTimeout = 3000;
                }

                stream.Write(richiesta, 0, richiesta.Length);

                int letti = 0;
                try
                {
                    letti = stream.Read(buffer, 0, buffer.Length);
                }
                catch (IOException)
                {
                    // Nessuna risposta entro il timeout: riprovo al giro dopo
                    letti = -1;
                }

                // 0 byte = il server ha chiuso la connessione: la riapro
                if (letti == 0)
                {
                    client.Close();
                    client = null;
                }
            }
            catch (Exception)
            {
                if (client != null)
                {
                    try { client.Close(); } catch (Exception) { }
                }
                client = null;
            }

            Thread.Sleep(5000);
        }

        if (client != null)
        {
            try { client.Close(); } catch (Exception) { }
        }

        return 0;
    }
}
'@

Clear-Host

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "   FALSO POSITIVO - TEST INNOCUO" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Questo test crea per pochi minuti una connessione TCP innocua" -ForegroundColor Yellow
Write-Host "verso ${HostTest}:${PortaTest} da un programma NON FIRMATO che" -ForegroundColor Yellow
Write-Host "si trova in .\fake_process\temp (accanto a questo script)." -ForegroundColor Yellow
Write-Host "Serve a verificare che controllo-connessioni lo segnali come" -ForegroundColor Yellow
Write-Host "SOSPETTO. A fine test viene tutto ripulito." -ForegroundColor Yellow
Write-Host ""
Write-Host "Premi INVIO per avviare il test (CTRL+C per annullare)..."
[void](Read-Host)

$proc = $null

try {

    # --------------------------------------------------------
    # Rimuove eventuali residui di un test precedente
    # --------------------------------------------------------

    if (Test-Path -LiteralPath $exePath) {

        Remove-Item -LiteralPath $exePath -Force -ErrorAction SilentlyContinue

        if (Test-Path -LiteralPath $exePath) {
            Write-Host "[ERRORE] Non riesco a rimuovere il vecchio file di test:" -ForegroundColor Red
            Write-Host "         $exePath" -ForegroundColor Red
            Write-Host "         Chiudi il processo 'falso_positivo_test' e riprova." -ForegroundColor Red
            return
        }
    }

    # --------------------------------------------------------
    # Compila il programma di test in .\fake_process\temp
    # --------------------------------------------------------

    Write-Host ""
    Write-Host "Compilazione del programma di test..." -ForegroundColor Yellow

    # Crea la cartella .\fake_process\temp se non esiste
    if (-not (Test-Path -LiteralPath $cartellaTest)) {
        New-Item `
            -ItemType Directory `
            -Path $cartellaTest `
            -Force |
            Out-Null
    }

    try {
        Add-Type `
            -TypeDefinition $codiceCSharp `
            -OutputAssembly $exePath `
            -OutputType ConsoleApplication `
            -ErrorAction Stop
    }
    catch {
        Write-Host "[ERRORE] Compilazione non riuscita:" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        return
    }

    if (-not (Test-Path -LiteralPath $exePath)) {
        Write-Host "[ERRORE] Il file di test non e' stato creato." -ForegroundColor Red
        return
    }

    Write-Host "Creato: $exePath" -ForegroundColor Green

    # --------------------------------------------------------
    # Avvia il programma di test (finestra nascosta)
    # --------------------------------------------------------

    $proc = Start-Process `
        -FilePath $exePath `
        -ArgumentList @($HostTest, $PortaTest, $DurataMaxSecondi) `
        -WindowStyle Hidden `
        -PassThru

    Write-Host "Programma di test avviato (PID $($proc.Id))." -ForegroundColor Green
    Write-Host "Attendo che la connessione risulti stabilita..." -ForegroundColor Yellow

    # --------------------------------------------------------
    # Verifica che la connessione sia davvero ESTABLISHED
    # --------------------------------------------------------

    $connessione = $null

    for ($i = 0; $i -lt 30; $i++) {

        Start-Sleep -Milliseconds 500

        if ($proc.HasExited) {
            break
        }

        $connessione = Get-NetTCPConnection `
            -OwningProcess $proc.Id `
            -State Established `
            -ErrorAction SilentlyContinue |
            Select-Object -First 1

        if ($connessione) {
            break
        }
    }

    Write-Host ""

    if ($connessione) {

        Write-Host "============================================================" -ForegroundColor Green
        Write-Host "[OK] Connessione di test ATTIVA" -ForegroundColor Green
        Write-Host "     PID       : $($proc.Id)" -ForegroundColor Green
        Write-Host "     Remoto    : $($connessione.RemoteAddress):$($connessione.RemotePort)" -ForegroundColor Green
        Write-Host "     Programma : $exePath" -ForegroundColor Green
        Write-Host "============================================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "ORA lancia run.bat (meglio come amministratore) in un'altra" -ForegroundColor Cyan
        Write-Host "finestra e cerca la riga 'falso_positivo_test':" -ForegroundColor Cyan
        Write-Host "l'esito atteso e' SOSPETTO (percorso/firma)." -ForegroundColor Cyan
    }
    else {

        Write-Host "[ATTENZIONE] Non vedo una connessione stabilita." -ForegroundColor Red
        Write-Host "Possibili cause: nessuna connessione internet, DNS che non" -ForegroundColor Red
        Write-Host "risolve $HostTest, firewall o antivirus che bloccano il" -ForegroundColor Red
        Write-Host "programma di test." -ForegroundColor Red

        if ($proc.HasExited) {
            Write-Host "(il programma di test e' gia' terminato)" -ForegroundColor Red
        }

        return
    }

    # --------------------------------------------------------
    # Attende: INVIO per terminare, oppure scade il tempo
    # --------------------------------------------------------

    Write-Host ""
    Write-Host "Premi INVIO per terminare il test e ripulire tutto." -ForegroundColor Yellow
    Write-Host "(Si ferma comunque da solo dopo $DurataMaxSecondi secondi.)" -ForegroundColor Yellow

    $fermatoConInvio = $false

    while (-not $proc.HasExited) {

        if ([Console]::KeyAvailable) {

            $tasto = [Console]::ReadKey($true)

            if ($tasto.Key -eq [ConsoleKey]::Enter) {
                $fermatoConInvio = $true
                break
            }
        }

        Start-Sleep -Milliseconds 300
    }

    # Il programma di test si e' fermato da solo (tempo scaduto) oppure
    # e' stato terminato da controllo-connessioni. NON ripulisco subito:
    # potresti dover ancora completare la quarantena o la whitelist, che
    # hanno bisogno del file. Aspetto il tuo INVIO.
    if (-not $fermatoConInvio) {

        Write-Host ""
        Write-Host "Il programma di test si e' fermato (terminato da" -ForegroundColor Yellow
        Write-Host "controllo-connessioni oppure tempo scaduto)." -ForegroundColor Yellow
        Write-Host "Completa pure quarantena/whitelist nell'altra finestra." -ForegroundColor Yellow
        Write-Host "Poi premi INVIO qui per ripulire i file di test." -ForegroundColor Yellow

        [void](Read-Host)
    }
}
finally {

    # --------------------------------------------------------
    # PULIZIA (eseguita sempre, anche con CTRL+C)
    # --------------------------------------------------------

    Write-Host ""
    Write-Host "Pulizia in corso..." -ForegroundColor Yellow

    if ($proc -and -not $proc.HasExited) {

        Stop-Process `
            -Id $proc.Id `
            -Force `
            -ErrorAction SilentlyContinue

        Start-Sleep -Milliseconds 500
    }

    # Il file puo' restare bloccato un istante dopo la chiusura
    # del processo: riprovo alcune volte.
    for ($t = 0; $t -lt 10; $t++) {

        if (-not (Test-Path -LiteralPath $exePath)) {
            break
        }

        Remove-Item `
            -LiteralPath $exePath `
            -Force `
            -ErrorAction SilentlyContinue

        if (Test-Path -LiteralPath $exePath) {
            Start-Sleep -Milliseconds 500
        }
    }

    if (Test-Path -LiteralPath $exePath) {
        Write-Host "[ATTENZIONE] Non sono riuscito a cancellare:" -ForegroundColor Red
        Write-Host "             $exePath" -ForegroundColor Red
        Write-Host "             Cancellalo a mano." -ForegroundColor Red
    }
    else {
        Write-Host "[OK] Programma di test fermato e file cancellato." -ForegroundColor Green
    }

    # Rimuove le cartelle di test, ma SOLO se sono vuote
    # (prima "temp", poi "fake_process")
    foreach ($cartella in @($cartellaTest, $cartellaFake)) {

        if (Test-Path -LiteralPath $cartella) {

            $contenuto = @(
                Get-ChildItem `
                    -LiteralPath $cartella `
                    -Force `
                    -ErrorAction SilentlyContinue
            )

            if ($contenuto.Count -eq 0) {
                Remove-Item `
                    -LiteralPath $cartella `
                    -Force `
                    -ErrorAction SilentlyContinue
            }
        }
    }

    Write-Host ""
    Write-Host "Test concluso." -ForegroundColor Green
}