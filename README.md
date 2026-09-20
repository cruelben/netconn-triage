# Outbound Connection Auditor

![Platform](https://img.shields.io/badge/platform-Windows-blue)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1-5391FE)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)

A dependency-free PowerShell tool for Windows that lists the **established outbound TCP connections** of your machine, checks the **path and digital signature** of the process behind each one, and flags the ones that look suspicious. For processes flagged as **SUSPICIOUS**, it can terminate them, move their files to quarantine, or add them to a hash-based whitelist.

It ships with a small **harmless test tool** that creates a fake suspicious connection, so you can verify that the detection really works on your machine.

> **Not an antivirus.** This is a quick, transparent triage tool built on standard Windows cmdlets. See [Limitations](#limitations-and-security-notes) before relying on it.

---

## Table of contents

- [Features](#features)
- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Files in this repository](#files-in-this-repository)
- [Quick start](#quick-start)
- [What you will see](#what-you-will-see)
- [Interactive actions](#interactive-actions)
- [Whitelist](#whitelist)
- [Quarantine](#quarantine)
- [Testing the detection (false positive tool)](#testing-the-detection-false-positive-tool)
- [Configuration](#configuration)
- [Limitations and security notes](#limitations-and-security-notes)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [Disclaimer](#disclaimer)

---

## Features

- Lists established TCP connections to **external** IPs only (loopback, private, link-local, CGNAT, multicast and reserved ranges are ignored, for both IPv4 and IPv6).
- For every process: executable path, **Authenticode signature status**, signer (publisher), company, file version.
- Classifies each process as `Normal`, `Whitelist`, `TO CHECK`, `SUSPICIOUS` or `UNVERIFIABLE`.
- **Terminates all suspicious processes** in one step (after your confirmation), with several safeguards against killing the wrong thing.
- Optional **quarantine**: moves the executables of terminated processes to a `Quarantine` folder, renamed so they cannot be executed. Nothing is deleted.
- **Whitelist by path + SHA256 hash**, not by name: if an approved file is replaced or modified, it is flagged again.
- Requires administrator rights via the launcher, so process paths can be read reliably.
- Pure PowerShell 5.1 + built-in Windows cmdlets. No downloads, no modules, no network calls made by the checker itself.
- All source files are plain ASCII (safe with Windows PowerShell 5.1 and BOM-less files).

## How it works

1. Reads all `Established` TCP connections with `Get-NetTCPConnection` and drops the ones whose remote address is local, private or multicast.
2. For each owning process (analyzed once, then cached), it collects:
   - the executable path (`Win32_Process.ExecutablePath`, falling back to `Get-Process`);
   - the signature status and signer (`Get-AuthenticodeSignature`);
   - company and version from the file's version info.
3. It assigns a status using the rules below.
4. For anything that is not `Normal`, it computes the file's SHA256 and checks it against the whitelist.
5. It prints a table, a verdict, a detail block per process to review, and (if needed) the interactive actions.

### Classification rules

| Situation | Status |
|---|---|
| Path cannot be read, running as admin, process is in `$knownProtectedProcesses` | `Normal (protected process)` |
| Path cannot be read (any other case) | `UNVERIFIABLE` |
| Path contains `\temp\` or `\downloads\`, signature **valid** | `TO CHECK (path)` |
| Path contains `\temp\` or `\downloads\`, signature **not valid** | `SUSPICIOUS (path/signature)` |
| Path contains `\appdata\`, signature valid **and** publisher in `$trustedPublishers` | `Normal` |
| Path contains `\appdata\`, signature valid, publisher not trusted | `TO CHECK (path)` |
| Path contains `\appdata\`, signature **not valid** | `SUSPICIOUS (path/signature)` |
| Any other path, signature **not valid** | `TO CHECK (signature)` |
| Any other path, signature valid | `Normal` |
| Any non-`Normal` process whose **path and SHA256** match a whitelist entry | `Whitelist` |

"Signature valid" means `Get-AuthenticodeSignature` returned `Valid`. Any other status (`NotSigned`, `NotTrusted`, `HashMismatch`, `UnknownError`, ...) is treated as not valid.

## Requirements

- Windows 10 or 11 (developed and tested on Windows 11; Windows 10 should work but is untested).
- **Windows PowerShell 5.1**, which is built into Windows. The launchers call `powershell.exe`, not PowerShell 7.
- **Administrator rights.** The launchers refuse to run without them.
- For the test tool only: internet access to `example.com:80` and the .NET Framework compiler that ships with Windows PowerShell 5.1.

## Files in this repository

| File | Purpose |
|---|---|
| `run.bat` | Launcher for the checker. Verifies administrator rights, then runs `controllo-connessioni.ps1`. |
| `controllo-connessioni.ps1` | The connection checker (*"controllo connessioni"* is Italian for *"connection check"*). |
| `falso_positivo.bat` | Launcher for the test tool. Same administrator check. |
| `falso_positivo.ps1` | The harmless test tool (*"falso positivo"* is Italian for *"false positive"*). |

Files created at runtime, next to the scripts:

| Path | Created by | Contents |
|---|---|---|
| `whitelist.txt` | checker | Approved processes (path + hash). |
| `Quarantine\` | checker | Quarantined files and `quarantine.txt` index. |
| `fake_process\temp\` | test tool | Temporary test executable (removed automatically). |

> These runtime files contain machine-specific paths and hashes. The provided `.gitignore` keeps them out of the repository.

## Quick start

```text
git clone https://github.com/cruelben/outbound-connection-auditor.git
cd outbound-connection-auditor
```

Or download the ZIP and extract it. Keep all four files in the same folder.

Then:

1. Right-click **`run.bat`** and choose **Run as administrator**.
2. Read the result table and the verdict.
3. If suspicious processes are found, answer the prompts (see [Interactive actions](#interactive-actions)).

If you start a launcher without administrator rights, it prints:

```text
WARNING: this script was NOT started as administrator.

Please run it again as administrator:
right-click this file, then "Run as administrator".
```

and exits after a key press, without running anything.

The launchers use `-ExecutionPolicy Bypass` for that single PowerShell process only; your system-wide execution policy is not changed.

## What you will see

Illustrative output (addresses use documentation ranges):

```text
PID  Process                Remote_IP      Remote_Port Local_Port Status                       Signature
---  -------                ---------      ----------- ---------- ------                       ---------
4992 chrome                 203.0.113.10          5228      46331 Normal                       Valid
4992 chrome                 203.0.113.25           443      41891 Normal                       Valid
9284 falso_positivo_test    198.51.100.7            80       1984 SUSPICIOUS (path/signature)  Unsigned
4316 MpDefenderCoreService  203.0.113.80           443      22927 Normal (protected process)   N/A

[WARNING] Suspicious connections: 1
```

After the table you get:

- a **verdict**: `[WARNING]` (suspicious found), `[INFO]` (nothing suspicious, but items need review) or `[OK]`;
- counters for `TO CHECK`, `UNVERIFIABLE` and `Whitelist` items;
- a **detail block per process to review**: PID, status, signature, publisher, company, version, SHA256, note and full path;
- a summary (connections found, rows after de-duplication, distinct processes).

Rows are de-duplicated per PID + remote IP + remote port.

## Interactive actions

Only `SUSPICIOUS` processes trigger prompts. They are listed first (PID, path, destinations), then:

```text
Terminate ALL the listed suspicious processes (this also closes their connections)? (Y/N):
```

### Answer `Y`: terminate

The script terminates the listed processes. **It terminates the process, not just the connection**: closing a single TCP connection is unreliable and the program would simply reconnect.

Safeguards applied before each termination:

1. Never terminates the script's own process, nor PID 0 or 4.
2. Never terminates processes listed in `$criticalProcesses` (`svchost`, `lsass`, `csrss`, `explorer`, ...) when they are located in `System32`.
3. Re-checks that the PID still belongs to the **same executable path** as at analysis time, because PIDs can be reassigned while you read the prompt. Skips it otherwise.
4. Reports processes that already ended, and any termination error, without stopping the run.

Then, if at least one process was terminated:

```text
Move the files of the terminated programs to quarantine? (Y/N):
```

See [Quarantine](#quarantine).

### Answer `N`: whitelist

Nothing is terminated. For each suspicious process, one at a time:

```text
Process : some_tool
Path    : C:\Users\me\Downloads\some_tool.exe
Add to the whitelist? (Y/N):
```

- `Y` -> saved to `whitelist.txt`; it will show as `Whitelist` from now on.
- `N` -> not saved; it will be flagged again next time.

Approval is per process on purpose: trusting a program is an individual decision.

## Whitelist

`whitelist.txt` lives next to the scripts and is plain text, one entry per line:

```text
# WHITELIST of controllo-connessioni.ps1
# Format: SHA256|Path|Process|DateAdded
SHA256HASH...|C:\Users\me\Downloads\some_tool.exe|some_tool|2026-01-01 12:00
```

- Lines starting with `#` and empty lines are ignored.
- An entry matches only if **both the path and the SHA256 hash** are identical (path comparison is case-insensitive).
- If the path is whitelisted but the hash differs (file updated or replaced), the process is **not** trusted and the detail block shows: *"Path is in the whitelist but the file has changed (different hash)"*.
- To remove an entry, delete its line.
- Processes whose file hash cannot be computed cannot be whitelisted.
- The whitelist is applied to every non-`Normal` process, so you can also add entries by hand for `TO CHECK` items.

## Quarantine

If you accept the quarantine step, each terminated program's executable is moved to `Quarantine\` (created next to the scripts) and renamed:

```text
Quarantine\20260101_120000_some_tool.exe.quarantine
```

The `.quarantine` extension prevents accidental execution. `Quarantine\quarantine.txt` records each move as:

```text
<new path>|<original path>
```

**To restore a file:** copy it back to the original path from `quarantine.txt` and remove the timestamp prefix and the `.quarantine` extension.

Quarantine is offered as a separate step because a terminated program may start again (autostart entries, scheduled tasks). Note that quarantining does not remove persistence mechanisms: if a program keeps coming back, inspect your startup entries and scheduled tasks (for example with Sysinternals Autoruns).

## Testing the detection (false positive tool)

To confirm the checker works on your machine, use the harmless test tool.

1. Right-click **`falso_positivo.bat`** and choose **Run as administrator**, then press ENTER.
2. The tool compiles a tiny **unsigned** executable, `falso_positivo_test.exe`, into `.\fake_process\temp\`, starts it, and confirms a real `Established` connection (PID and remote address are printed).
3. In another window, run **`run.bat`** as administrator. You should see `falso_positivo_test` with status `SUSPICIOUS (path/signature)`.
4. Try the interactive actions on it:
   - answer **Y** to terminate it, then **Y** to quarantine it;
   - or answer **N** and whitelist it, then run `run.bat` again: it should now show as `Whitelist`;
   - stop the test and start it again: the executable is recompiled, so its hash will most likely differ and it should be flagged again with the "file has changed" note.
5. Back in the test window, press **ENTER** to clean up. If the checker terminated the test program, the test tool waits for your ENTER before cleaning up, so the quarantine step still finds the file.

What the test program does:

- opens one TCP connection to `example.com:80` (a domain reserved by IANA for documentation and tests);
- sends an HTTP `HEAD /` request every 5 seconds to keep the connection alive, reopening it if the server closes it;
- stops by itself after 300 seconds (`$MaxDurationSeconds`).

What it does **not** do: modify the system or registry, touch your files, or transmit any of your data. Cleanup removes the executable and the `temp` and `fake_process` folders (only if empty).

**Why the subfolder is called `temp`:** the checker flags an *unsigned* program as `SUSPICIOUS` only when its path contains `\temp\`, `\downloads\` or `\appdata\`. In a "normal" folder it would only be `TO CHECK (signature)`.

The test tool needs Windows PowerShell 5.1 (`Add-Type -OutputAssembly` is not available in PowerShell 7). Some antivirus or firewall products may block or quarantine the test executable, since it is unsigned and opens an outbound connection.

## Configuration

Edit the variables at the top of `controllo-connessioni.ps1`:

| Variable | Meaning |
|---|---|
| `$trustedPublishers` | Publishers trusted for programs under `\AppData\`. A valid signature from one of these makes the program `Normal` (avoids false positives for Discord, Spotify, Chrome, ...). The exact name to use appears in the `Publisher` field of the detail block. |
| `$knownProtectedProcesses` | Protected system processes whose path cannot be read even as administrator (default: `MpDefenderCoreService`). Treated as `Normal` only when running as administrator. |
| `$criticalProcesses` | Processes that are never terminated when located in `System32`. |

In `falso_positivo.ps1`:

| Variable | Meaning |
|---|---|
| `$TestHost`, `$TestPort` | Destination of the test connection (default `example.com:80`). |
| `$MaxDurationSeconds` | Maximum duration of the test program (default 300). |

## Limitations and security notes

- **Snapshot only.** It shows what is connected at the moment you run it. Short-lived connections can be missed.
- **TCP only.** UDP is not inspected, so QUIC/HTTP3 traffic (used by modern browsers) does not appear.
- **A "Normal" status is not a guarantee of safety.** Malware can be signed, can live in `Program Files`, or can inject code into a legitimate process (for example a browser or `svchost`). The tool reports on *processes and their files*, not on the content of the traffic.
- **`AppData` produces false positives.** Many legitimate per-user applications live there. Use `$trustedPublishers` and the whitelist to tune this.
- **Terminating processes can disrupt work.** Data in a terminated application may be lost. Read the list before answering `Y`.
- **Quarantine is manual to reverse** (see [Quarantine](#quarantine)).
- The whitelist protects against file replacement thanks to the hash, but anyone who can edit `whitelist.txt` can approve anything: keep the folder writable only by trusted users.
- Use it on machines you own or administer.

For deeper investigation, combine it with tools such as Sysinternals TCPView, Process Explorer (with VirusTotal checks) and Autoruns, plus your antivirus/EDR.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Launcher says the script was not started as administrator | Right-click the `.bat` and choose **Run as administrator**. |
| Many processes show `UNVERIFIABLE` | The script is not elevated, or the process is protected by Windows. Run as administrator; add known protected names to `$knownProtectedProcesses`. |
| A well-known app shows `TO CHECK (path)` | It runs from `\AppData\`. Add its publisher (as shown in the detail block) to `$trustedPublishers`, or whitelist it. |
| A whitelisted app is flagged again | Its file changed (update). The detail block shows the "different hash" note. Approve it again if you trust the new version. |
| Test tool: "Compilation failed" | It must run under Windows PowerShell 5.1 (use `falso_positivo.bat`). |
| Test tool: "I do not see an established connection" | No internet, DNS failure for the test host, or a firewall/antivirus blocking the test program. |
| Test tool could not delete its executable | Close the `falso_positivo_test` process and delete the file by hand. |
| Accented characters look wrong | All scripts are ASCII on purpose; if you edit them, avoid non-ASCII characters or save with a UTF-8 BOM. |

## Contributing

Issues and pull requests are welcome. Please keep the scripts compatible with **Windows PowerShell 5.1**, dependency-free, and ASCII-only.

## Disclaimer

This software is provided "as is", without warranty of any kind. It can terminate processes and move files; review what it proposes before confirming. You are responsible for how you use it.

<!-- Add a LICENSE file (for example MIT) and reference it here before publishing. -->
