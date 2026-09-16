#Requires -Version 5.1
<#
.SYNOPSIS
Tests network prerequisites for CrowdStrike Falcon Sensor on Windows.
.EXAMPLE
.\Test-CrowdStrikeConnection.ps1 -Cloud US-2
.EXAMPLE
.\Test-CrowdStrikeConnection.ps1 -Cloud US-1 -ConnectionMode Direct -CheckRevocation
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('US-1', 'US-2', 'EU-1')][string]$Cloud,
    [ValidateSet('Auto', 'Direct')][string]$ConnectionMode = 'Auto',
    [ValidateRange(1, 60)][int]$TimeoutSeconds = 10,
    [switch]$CheckRevocation,
    [switch]$IncludeConsole,
    [string[]]$AdditionalHost = @(),
    [string]$OutputDirectory = (Join-Path $PSScriptRoot 'reports')
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
try {
    if ($env:OS -ne 'Windows_NT') { throw 'This entry point supports Windows only.' }
    Import-Module (Join-Path $PSScriptRoot 'src/Preflight.psm1') -Force
    $targets = @(Get-PreflightTargets -Cloud $Cloud -IncludeConsole:$IncludeConsole -AdditionalHost $AdditionalHost | Sort-Object Hostname -Unique)
    Initialize-Probe
    $null = New-Item -Path $OutputDirectory -ItemType Directory -Force
    $reportName = 'FalconPreflight-{0}-{1}' -f (Get-Date -Format 'yyyyMMdd-HHmmss'), ([guid]::NewGuid().ToString('N').Substring(0, 8))
    $reportBase = Join-Path $OutputDirectory $reportName
    $proxyInventory = [ordered]@{ WinHTTP = ''; CurrentUser = $null }
    try { $proxyInventory.WinHTTP = (& netsh winhttp show proxy 2>&1 | Out-String).Trim() } catch { $proxyInventory.WinHTTP = $_.Exception.Message }
    try {
        $settings = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
        $proxyInventory.CurrentUser = $settings | Select-Object ProxyEnable, ProxyServer, AutoConfigURL, ProxyOverride
    } catch { $proxyInventory.CurrentUser = 'Unavailable' }
    $results = New-Object 'System.Collections.Generic.List[object]'
    Write-Host "CrowdStrike pre-deployment connectivity test | Cloud=$Cloud | Mode=$ConnectionMode"
    Write-Host 'Checks TLS 1.2 with certificate validation. Does not change system settings.'
    Write-Host 'PASS is a network result, not proof of Sensor registration or absence of TLS inspection.'
    $milliseconds = $TimeoutSeconds * 1000
    foreach ($target in $targets) {
        Write-Host "Testing $($target.Hostname) ..."
        $attempts = @()
        $dns = @()
        $dnsError = $null
        $route = 'Direct'
        $proxy = $null
        $stage = 'ProxyDetection'
        try {
            if ($ConnectionMode -eq 'Auto') { $proxy = [FalconPreflight.NetworkProbe]::SystemProxy($target.Hostname, $milliseconds) }
            if ($null -ne $proxy) {
                $route = 'http://{0}:{1}' -f $proxy.Host, $proxy.Port
                if ($proxy.Scheme -ne 'http' -or $proxy.UserInfo) { throw 'Detected proxy scheme/credentials are unsupported. No direct fallback was attempted.' }
            }
            $stage = 'DNS'
            try { $dns = @([FalconPreflight.NetworkProbe]::Resolve($target.Hostname, $milliseconds) | ForEach-Object { $_.ToString() }) }
            catch { $dnsError = $_.Exception.GetBaseException().Message; if ($null -eq $proxy) { throw } }
            # An HTTP proxy resolves the target remotely; local target DNS is advisory on this path.
            $addresses = if ($null -ne $proxy) { @([FalconPreflight.NetworkProbe]::Resolve($proxy.Host, $milliseconds)) } else { @($dns | ForEach-Object { [System.Net.IPAddress]::Parse($_) }) }
            if ($addresses.Count -eq 0) { throw 'No addresses returned by DNS.' }
            foreach ($address in $addresses) {
                $attempts += [FalconPreflight.NetworkProbe]::Test($target.Hostname, 443, $address, $proxy, $milliseconds, $CheckRevocation.IsPresent)
            }
            $status = Get-EndpointStatus -Attempts $attempts
        } catch {
            $status = 'FAIL'
            $attempts += [pscustomobject]@{ Target = $target.Hostname; Route = $route; Address = ''; Stage = $stage; Success = $false; Error = $_.Exception.GetBaseException().Message }
        }
        $entry = [pscustomobject]@{
            Hostname = $target.Hostname; Required = $target.Required; Category = $target.Category
            Status = $status; Route = $route; DNS = $dns; DNSError = $dnsError; Attempts = $attempts
        }
        $results.Add($entry)
        $color = switch ($status) { 'PASS' { 'Green' }; 'WARN' { 'Yellow' }; default { 'Red' } }
        Write-Host "[$status] $($target.Hostname) via $route" -ForegroundColor $color
        foreach ($attempt in $attempts) {
            if (-not $attempt.Success) { Write-Host "  $($attempt.Address) $($attempt.Stage): $($attempt.Error)" -ForegroundColor Yellow }
        }
    }
    $exitCode = Get-PreflightExitCode -Results $results.ToArray()
    $report = [ordered]@{
        SchemaVersion = 1; ToolVersion = '1.0.0'; GeneratedAtUtc = [DateTime]::UtcNow.ToString('o')
        ComputerName = $env:COMPUTERNAME; OS = [Environment]::OSVersion.VersionString
        PowerShellVersion = $PSVersionTable.PSVersion.ToString(); Is64BitProcess = [Environment]::Is64BitProcess
        Cloud = $Cloud; ConnectionMode = $ConnectionMode; TimeoutSeconds = $TimeoutSeconds
        RevocationChecked = $CheckRevocation.IsPresent; ProxyInventory = $proxyInventory
        ExitCode = $exitCode; Results = $results.ToArray()
        Limitations = @('Generic TLS 1.2 probe; does not emulate Sensor certificate pinning or client authentication.', 'Auto uses current process .NET system proxy; Sensor service and WinHTTP configuration may differ.', 'PASS does not establish Sensor registration, supported OS/KBs, or absence of TLS interception.', 'Revocation is only requested when CheckRevocation is set; OS cache and policy apply.')
    }
    $report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath "$reportBase.json" -Encoding UTF8
    $results | Select-Object Hostname, Category, Required, Status, Route, @{Name='DNS';Expression={$_.DNS -join ';'}}, DNSError, @{Name='Details';Expression={($_.Attempts | ForEach-Object { "$($_.Address) $($_.Stage) $($_.Error)" }) -join ' | '}} | Export-Csv -LiteralPath "$reportBase.csv" -NoTypeInformation -Encoding UTF8
    $textReport = @("CrowdStrike pre-deployment connectivity test", "Cloud: $Cloud | Mode: $ConnectionMode | ExitCode: $exitCode", ($results | Format-Table Hostname, Status, Route -AutoSize | Out-String -Width 240), ($results | ForEach-Object { $_.Attempts | Format-List * | Out-String -Width 240 }), $report.Limitations)
    $textReport | Set-Content -LiteralPath "$reportBase.txt" -Encoding UTF8
    Write-Host "Reports: $reportBase.[json|csv|txt]"
    Write-Host "Exit code: $exitCode (0=network checks passed, 1=required endpoint failed, 2=review warnings, 3=tool error)"
    exit $exitCode
} catch {
    Write-Error -Message $_.Exception.Message -ErrorAction Continue
    exit 3
}
