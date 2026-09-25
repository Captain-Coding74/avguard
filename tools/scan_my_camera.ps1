<#
.SYNOPSIS
    Audit a Wi-Fi camera (or any device) on a network you control.

.DESCRIPTION
    A home security check for your OWN camera. It finds the device, runs an
    nmap service scan, and flags the weaknesses that budget IP cameras
    (V380 Pro / Macrovideo and similar) are known for: open telnet, an
    unauthenticated RTSP stream, stale web servers, and other listening
    services you did not put there.

    This tool only tells you what is exposed so you can close it. It does not
    log in, guess passwords, or exploit anything -- knowing a port is open and
    a service is old is what tells you what to fix. Run it only against a
    device on a network you own or administer.

.PARAMETER Target
    The camera's IP address. If omitted, the script uses your Wi-Fi adapter's
    default gateway, which for a camera running its own hotspot (AP mode) is
    usually the camera itself.

.PARAMETER Full
    Scan all 65535 ports (nmap -p-) instead of nmap's top ~1000. Slower, but
    it catches services hidden on odd ports -- exactly where these cameras
    tend to leave telnet and debug backdoors. Recommended for a real audit.

.PARAMETER OutFile
    Optional path to save the raw nmap output for your records.

.EXAMPLE
    .\scan_my_camera.ps1
    Scan the default gateway (the camera, in AP mode) on the common ports.

.EXAMPLE
    .\scan_my_camera.ps1 -Target 192.168.1.1 -Full
    Full 65535-port audit of a specific camera IP.

.NOTES
    Prerequisite: nmap for Windows (https://nmap.org/download). Install it
    with the bundled Npcap driver, then reopen PowerShell so nmap is on PATH.
#>

[CmdletBinding()]
param(
    [string]$Target,
    [switch]$Full,
    [string]$OutFile
)

$ErrorActionPreference = 'Stop'

function Write-Section($text) {
    Write-Host ''
    Write-Host ('=' * 62) -ForegroundColor DarkCyan
    Write-Host "  $text" -ForegroundColor Cyan
    Write-Host ('=' * 62) -ForegroundColor DarkCyan
}

# --- 1. Confirm nmap is installed -----------------------------------------
$nmap = Get-Command nmap -ErrorAction SilentlyContinue
if (-not $nmap) {
    Write-Host "nmap was not found on PATH." -ForegroundColor Red
    Write-Host "Install it from https://nmap.org/download (keep the Npcap"
    Write-Host "option checked), then reopen PowerShell and run this again."
    exit 1
}

# --- 2. Work out what to scan ---------------------------------------------
if (-not $Target) {
    Write-Section "Finding the camera"
    # The default gateway of the active Wi-Fi connection. In AP mode the
    # camera IS the gateway; on a home router this finds the router, so pass
    # -Target explicitly there once you know the camera's IP.
    $gw = Get-NetIPConfiguration |
        Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq 'Up' } |
        Select-Object -First 1 -ExpandProperty IPv4DefaultGateway |
        Select-Object -ExpandProperty NextHop

    if (-not $gw) {
        Write-Host "Could not read a default gateway. Are you connected to"   -ForegroundColor Red
        Write-Host "the camera's Wi-Fi? Pass the IP directly: -Target 192.168.1.1"
        exit 1
    }
    $Target = $gw
    Write-Host "Using default gateway as the target: $Target" -ForegroundColor Green
    Write-Host "(If your camera is on your home router instead, re-run with"
    Write-Host " -Target set to the camera's own IP from the router's device list.)"
}

# Sanity-check it looks like an IPv4 address.
if ($Target -notmatch '^\d{1,3}(\.\d{1,3}){3}$') {
    Write-Host "'$Target' does not look like an IPv4 address." -ForegroundColor Red
    exit 1
}

# --- 3. Reachability ------------------------------------------------------
Write-Section "Checking $Target is reachable"
if (Test-Connection -ComputerName $Target -Count 2 -Quiet) {
    Write-Host "Host is up." -ForegroundColor Green
} else {
    Write-Host "No ping reply. Some cameras block ping but still answer a"    -ForegroundColor Yellow
    Write-Host "scan, so continuing anyway."
}

# --- 4. Run the scan ------------------------------------------------------
Write-Section "Scanning services on $Target"
$portArg = if ($Full) { '-p-' } else { '' }
$scope   = if ($Full) { 'all 65535 ports' } else { "nmap's top ~1000 ports" }
Write-Host "Scanning $scope with version detection. This can take a few"
Write-Host "minutes on a full scan -- let it finish." -ForegroundColor DarkGray

# -sV service/version detection, -T4 reasonable speed on a LAN you own,
# --version-intensity 9 tries harder to fingerprint firmware for CVE lookup.
$nmapArgs = @('-sV', '-T4', '--version-intensity', '9')
if ($portArg) { $nmapArgs += $portArg }
$nmapArgs += $Target

$raw = & nmap @nmapArgs 2>&1 | Out-String
Write-Host $raw

if ($OutFile) {
    $raw | Out-File -FilePath $OutFile -Encoding utf8
    Write-Host "Raw output saved to $OutFile" -ForegroundColor Green
}

# --- 5. Flag the risky findings -------------------------------------------
Write-Section "Findings"

# Parse "PORT   STATE SERVICE VERSION" lines that are open.
$openLines = $raw -split "`r?`n" | Where-Object { $_ -match '^\d+/tcp\s+open' }

if (-not $openLines) {
    Write-Host "No open TCP ports were reported. Either the camera is well"   -ForegroundColor Green
    Write-Host "locked down, it blocked the scan, or it is not at $Target."
    Write-Host "If you expected ports open, try -Full, or confirm the IP."
    exit 0
}

# Each rule: a regex over the nmap line, a severity, and what to do about it.
$rules = @(
    @{ Match = 'telnet';                       Sev = 'HIGH';   Note = 'Telnet is open. Budget cameras often leave it on with a hardcoded password. Disable it in the app/firmware, or block the port. This is the single worst finding.' }
    @{ Match = '(^|\s)23/tcp';                 Sev = 'HIGH';   Note = 'Port 23 (telnet) open -- see above. There is no safe reason for a camera to expose telnet.' }
    @{ Match = 'ftp';                          Sev = 'MEDIUM'; Note = 'FTP is open, often with anonymous or default login and no encryption. Disable it unless you deliberately pull footage this way.' }
    @{ Match = '(^|\s)554/tcp|rtsp';           Sev = 'MEDIUM'; Note = 'RTSP video stream. Test whether it needs a password: open rtsp://<ip>:554/ in VLC. If the video plays with no login, anyone on this network can watch. Set an RTSP password in the app.' }
    @{ Match = '(^|\s)22/tcp|ssh';             Sev = 'MEDIUM'; Note = 'SSH is open. Fine only if you set it up and use a strong password/key; on a camera it is usually a leftover debug service -- disable it if you did not enable it.' }
    @{ Match = '(^|\s)80/tcp|(^|\s)8080/tcp|http'; Sev = 'INFO'; Note = 'A web interface is exposed. Make sure it requires a strong, non-default password. Note the server/version string for a CVE lookup.' }
    @{ Match = '(^|\s)8000/tcp|(^|\s)34567/tcp';   Sev = 'INFO'; Note = 'A common camera control/ONVIF port. Confirm it is password-protected and not reachable from outside your LAN.' }
    @{ Match = 'upnp|(^|\s)1900';              Sev = 'MEDIUM'; Note = 'UPnP present. Cameras use it to auto-open ports on your router, which can silently expose the camera to the internet. Turn UPnP off on your router.' }
)

$hits = @()
foreach ($line in $openLines) {
    $matched = $false
    foreach ($rule in $rules) {
        if ($line -match $rule.Match) {
            $hits += [pscustomobject]@{ Sev = $rule.Sev; Line = $line.Trim(); Note = $rule.Note }
            $matched = $true
        }
    }
    if (-not $matched) {
        $hits += [pscustomobject]@{ Sev = 'INFO'; Line = $line.Trim(); Note = 'Open port with no specific rule. Confirm you know why it is open; note the version for a CVE lookup.' }
    }
}

# De-duplicate (a line can match more than one rule) and sort by severity.
$order = @{ 'HIGH' = 0; 'MEDIUM' = 1; 'INFO' = 2 }
$hits = $hits | Sort-Object @{ Expression = { $order[$_.Sev] } }, Line -Unique

foreach ($h in $hits) {
    $color = switch ($h.Sev) { 'HIGH' { 'Red' } 'MEDIUM' { 'Yellow' } default { 'Gray' } }
    Write-Host ''
    Write-Host ("[{0}] {1}" -f $h.Sev, $h.Line) -ForegroundColor $color
    Write-Host ("       -> {0}" -f $h.Note)
}

Write-Section "Next steps"
Write-Host @"
1. Change the camera's device password AND your V380 account password to
   something long and unique. Enable 2FA in the app if it offers it.
2. Check for a firmware update in the app (Settings -> Device -> firmware).
3. Look up '<model> <firmware version> CVE' for the versions nmap reported.
4. Put the camera on a guest/IoT Wi-Fi network so it cannot see your PC,
   phone, or other devices even if it is compromised.
5. Turn UPnP off on your router so the camera cannot expose itself to the
   internet on its own.

Paste this output back into the chat and I will interpret it line by line.
"@
