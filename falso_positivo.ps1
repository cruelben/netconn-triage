# ============================================================
# FALSE POSITIVE - HARMLESS TEST FOR controllo-connessioni.ps1
# ============================================================
# What it does:
#   1. Compiles a tiny UNSIGNED program in a "temp" subfolder
#      inside .\fake_process (i.e. next to this script).
#      The name "temp" in the path, together with the missing
#      signature, makes it "suspicious" for controllo-connessioni.ps1.
#   2. Starts it: the program opens ONE TCP connection to a public
#      test site and keeps it open.
#   3. Waits while you run run.bat and check the result.
#   4. At the end (ENTER, CTRL+C or time expired) it stops the
#      program and deletes the compiled file.
#
# What it does NOT do:
#   - it does not modify the system, the registry or your files
#   - it does not download or send any data of yours: it only sends
#     an HTTP "HEAD /" request every 5 seconds to $TestHost
#   - it does not keep running: it stops by itself after
#     $MaxDurationSeconds
#
# Expected outcome in controllo-connessioni.ps1:
#   Process: falso_positivo_test
#   Status : SUSPICIOUS (path/signature)
#
# NOTE: requires Windows PowerShell 5.1 (the one started by
# falso_positivo.bat), not PowerShell 7.
# ============================================================

# ------------------------------------------------------------
# CONFIGURATION
# ------------------------------------------------------------

# Test site: example.com is a domain reserved by IANA
# precisely for tests and documentation.
$TestHost = "example.com"
$TestPort = 80

# Maximum test duration (then the program stops by itself)
$MaxDurationSeconds = 300

# Script folder (same as falso_positivo.bat)
$scriptFolder = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($scriptFolder)) {
    $scriptFolder = (Get-Location).Path
}

# Path of the test program: .\fake_process\temp\
# WARNING: the subfolder must be called "temp" (or "downloads"):
# controllo-connessioni.ps1 considers an unsigned program SUSPICIOUS
# only if its path contains \temp\, \downloads\ or \appdata\.
# In a "normal" folder it would only be classified as TO CHECK.
$exeName = "falso_positivo_test.exe"
$fakeFolder = Join-Path $scriptFolder "fake_process"
$testFolder = Join-Path $fakeFolder "temp"
$exePath = Join-Path $testFolder $exeName

# ------------------------------------------------------------
# C# CODE OF THE TEST PROGRAM
# ------------------------------------------------------------
# Opens a TCP connection, sends a HEAD request every 5 seconds
# to keep it alive and, if the server closes it, reopens it.
# When the time is up, it exits.

$csharpCode = @'
using System;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Threading;

public static class FalsePositiveTest
{
    public static int Main(string[] args)
    {
        string host = "example.com";
        int port = 80;
        int seconds = 120;

        if (args.Length > 0) { host = args[0]; }
        if (args.Length > 1) { int.TryParse(args[1], out port); }
        if (args.Length > 2) { int.TryParse(args[2], out seconds); }

        DateTime end = DateTime.UtcNow.AddSeconds(seconds);

        byte[] request = Encoding.ASCII.GetBytes(
            "HEAD / HTTP/1.1\r\nHost: " + host +
            "\r\nConnection: keep-alive\r\n\r\n");

        byte[] buffer = new byte[4096];
        TcpClient client = null;
        NetworkStream stream = null;

        while (DateTime.UtcNow < end)
        {
            try
            {
                if (client == null)
                {
                    client = new TcpClient();
                    client.Connect(host, port);
                    stream = client.GetStream();
                    stream.ReadTimeout = 3000;
                }

                stream.Write(request, 0, request.Length);

                int bytesRead = 0;
                try
                {
                    bytesRead = stream.Read(buffer, 0, buffer.Length);
                }
                catch (IOException)
                {
                    // No reply within the timeout: try again next round
                    bytesRead = -1;
                }

                // 0 bytes = the server closed the connection: reopen it
                if (bytesRead == 0)
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
Write-Host "   FALSE POSITIVE - HARMLESS TEST" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "For a few minutes, this test creates a harmless TCP connection" -ForegroundColor Yellow
Write-Host "to ${TestHost}:${TestPort} from an UNSIGNED program located in" -ForegroundColor Yellow
Write-Host ".\fake_process\temp (next to this script)." -ForegroundColor Yellow
Write-Host "It is used to check that controllo-connessioni flags it as" -ForegroundColor Yellow
Write-Host "SUSPICIOUS. Everything is cleaned up at the end of the test." -ForegroundColor Yellow
Write-Host ""
Write-Host "Press ENTER to start the test (CTRL+C to cancel)..."
[void](Read-Host)

$proc = $null

try {

    # --------------------------------------------------------
    # Remove any leftovers from a previous test
    # --------------------------------------------------------

    if (Test-Path -LiteralPath $exePath) {

        Remove-Item -LiteralPath $exePath -Force -ErrorAction SilentlyContinue

        if (Test-Path -LiteralPath $exePath) {
            Write-Host "[ERROR] Cannot remove the old test file:" -ForegroundColor Red
            Write-Host "        $exePath" -ForegroundColor Red
            Write-Host "        Close the 'falso_positivo_test' process and try again." -ForegroundColor Red
            return
        }
    }

    # --------------------------------------------------------
    # Compile the test program in .\fake_process\temp
    # --------------------------------------------------------

    Write-Host ""
    Write-Host "Compiling the test program..." -ForegroundColor Yellow

    # Create the .\fake_process\temp folder if it does not exist
    if (-not (Test-Path -LiteralPath $testFolder)) {
        New-Item `
            -ItemType Directory `
            -Path $testFolder `
            -Force |
            Out-Null
    }

    try {
        Add-Type `
            -TypeDefinition $csharpCode `
            -OutputAssembly $exePath `
            -OutputType ConsoleApplication `
            -ErrorAction Stop
    }
    catch {
        Write-Host "[ERROR] Compilation failed:" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        return
    }

    if (-not (Test-Path -LiteralPath $exePath)) {
        Write-Host "[ERROR] The test file was not created." -ForegroundColor Red
        return
    }

    Write-Host "Created: $exePath" -ForegroundColor Green

    # --------------------------------------------------------
    # Start the test program (hidden window)
    # --------------------------------------------------------

    $proc = Start-Process `
        -FilePath $exePath `
        -ArgumentList @($TestHost, $TestPort, $MaxDurationSeconds) `
        -WindowStyle Hidden `
        -PassThru

    Write-Host "Test program started (PID $($proc.Id))." -ForegroundColor Green
    Write-Host "Waiting for the connection to be established..." -ForegroundColor Yellow

    # --------------------------------------------------------
    # Check that the connection is really ESTABLISHED
    # --------------------------------------------------------

    $connection = $null

    for ($i = 0; $i -lt 30; $i++) {

        Start-Sleep -Milliseconds 500

        if ($proc.HasExited) {
            break
        }

        $connection = Get-NetTCPConnection `
            -OwningProcess $proc.Id `
            -State Established `
            -ErrorAction SilentlyContinue |
            Select-Object -First 1

        if ($connection) {
            break
        }
    }

    Write-Host ""

    if ($connection) {

        Write-Host "============================================================" -ForegroundColor Green
        Write-Host "[OK] Test connection ACTIVE" -ForegroundColor Green
        Write-Host "     PID     : $($proc.Id)" -ForegroundColor Green
        Write-Host "     Remote  : $($connection.RemoteAddress):$($connection.RemotePort)" -ForegroundColor Green
        Write-Host "     Program : $exePath" -ForegroundColor Green
        Write-Host "============================================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "NOW run run.bat (as administrator) in another window and" -ForegroundColor Cyan
        Write-Host "look for the 'falso_positivo_test' row:" -ForegroundColor Cyan
        Write-Host "the expected outcome is SUSPICIOUS (path/signature)." -ForegroundColor Cyan
    }
    else {

        Write-Host "[WARNING] I do not see an established connection." -ForegroundColor Red
        Write-Host "Possible causes: no internet connection, DNS not resolving" -ForegroundColor Red
        Write-Host "$TestHost, or a firewall/antivirus blocking the test" -ForegroundColor Red
        Write-Host "program." -ForegroundColor Red

        if ($proc.HasExited) {
            Write-Host "(the test program has already ended)" -ForegroundColor Red
        }

        return
    }

    # --------------------------------------------------------
    # Wait: ENTER to finish, or until the time expires
    # --------------------------------------------------------

    Write-Host ""
    Write-Host "Press ENTER to end the test and clean everything up." -ForegroundColor Yellow
    Write-Host "(It stops by itself anyway after $MaxDurationSeconds seconds.)" -ForegroundColor Yellow

    $stoppedWithEnter = $false

    while (-not $proc.HasExited) {

        if ([Console]::KeyAvailable) {

            $key = [Console]::ReadKey($true)

            if ($key.Key -eq [ConsoleKey]::Enter) {
                $stoppedWithEnter = $true
                break
            }
        }

        Start-Sleep -Milliseconds 300
    }

    # The test program stopped by itself (time expired) or was
    # terminated by controllo-connessioni. Do NOT clean up right away:
    # you may still need to complete the quarantine or the whitelist,
    # which need the file. Wait for your ENTER.
    if (-not $stoppedWithEnter) {

        Write-Host ""
        Write-Host "The test program has stopped (terminated by" -ForegroundColor Yellow
        Write-Host "controllo-connessioni or time expired)." -ForegroundColor Yellow
        Write-Host "Finish the quarantine/whitelist in the other window." -ForegroundColor Yellow
        Write-Host "Then press ENTER here to clean up the test files." -ForegroundColor Yellow

        [void](Read-Host)
    }
}
finally {

    # --------------------------------------------------------
    # CLEANUP (always executed, even with CTRL+C)
    # --------------------------------------------------------

    Write-Host ""
    Write-Host "Cleaning up..." -ForegroundColor Yellow

    if ($proc -and -not $proc.HasExited) {

        Stop-Process `
            -Id $proc.Id `
            -Force `
            -ErrorAction SilentlyContinue

        Start-Sleep -Milliseconds 500
    }

    # The file may stay locked for a moment after the process
    # closes: retry a few times.
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
        Write-Host "[WARNING] I could not delete:" -ForegroundColor Red
        Write-Host "          $exePath" -ForegroundColor Red
        Write-Host "          Delete it by hand." -ForegroundColor Red
    }
    else {
        Write-Host "[OK] Test program stopped and file deleted." -ForegroundColor Green
    }

    # Remove the test folders, but ONLY if they are empty
    # (first "temp", then "fake_process")
    foreach ($folder in @($testFolder, $fakeFolder)) {

        if (Test-Path -LiteralPath $folder) {

            $contents = @(
                Get-ChildItem `
                    -LiteralPath $folder `
                    -Force `
                    -ErrorAction SilentlyContinue
            )

            if ($contents.Count -eq 0) {
                Remove-Item `
                    -LiteralPath $folder `
                    -Force `
                    -ErrorAction SilentlyContinue
            }
        }
    }

    Write-Host ""
    Write-Host "Test finished." -ForegroundColor Green
}
