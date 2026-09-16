Set-StrictMode -Version 2.0
function Initialize-Probe {
    if (-not ('FalconPreflight.NetworkProbe' -as [type])) {
        Add-Type -Path (Join-Path $PSScriptRoot 'NetworkProbe.cs')
    }
}
function Get-PreflightTargets {
    param([string]$Cloud, [switch]$IncludeConsole, [string[]]$AdditionalHost)
    $sensorHosts = @{
        'US-1' = @('ts01-b.cloudsink.net', 'lfodown01-b.cloudsink.net', 'lfoup01-b.cloudsink.net')
        'US-2' = @('ts01-gyr-maverick.cloudsink.net', 'lfodown01-gyr-maverick.cloudsink.net', 'lfoup01-gyr-maverick.cloudsink.net')
        'US-3' = @('ts01.us-3.cloudsink.net', 'lfodown01.us-3.cloudsink.net')
        'EU-1' = @('ts01-lanner-lion.cloudsink.net', 'lfodown01-lanner-lion.cloudsink.net', 'lfoup01-lanner-lion.cloudsink.net')
    }
    if (-not $sensorHosts.ContainsKey($Cloud)) { throw "Unsupported cloud: $Cloud" }
    foreach ($name in $sensorHosts[$Cloud]) {
        [pscustomobject]@{ Hostname = $name; Required = $true; Category = 'Sensor' }
    }
    if ($IncludeConsole) {
        $domain = switch ($Cloud) { 'US-1' { 'crowdstrike.com' }; 'US-2' { 'us-2.crowdstrike.com' }; 'US-3' { 'us-3.crowdstrike.com' }; 'EU-1' { 'eu-1.crowdstrike.com' } }
        foreach ($name in @("falcon.$domain", "api.$domain")) {
            [pscustomobject]@{ Hostname = $name; Required = $false; Category = 'Console/API' }
        }
    }
    foreach ($name in $AdditionalHost) {
        if ([string]::IsNullOrWhiteSpace($name) -or [Uri]::CheckHostName($name) -ne [UriHostNameType]::Dns -or $name -match '[^a-zA-Z0-9.-]' -or $name -notmatch '\.') {
            throw "AdditionalHost must be a DNS hostname without a URL, wildcard, port or credentials: $name"
        }
        [pscustomobject]@{ Hostname = $name.ToLowerInvariant(); Required = $true; Category = 'Additional' }
    }
}
function Get-EndpointStatus {
    param([object[]]$Attempts)
    $successful = @($Attempts | Where-Object { $_.Success }).Count
    if ($successful -eq 0) { return 'FAIL' }
    if ($successful -ne $Attempts.Count) { return 'WARN' }
    return 'PASS'
}
function Get-PreflightExitCode {
    param([object[]]$Results)
    if (@($Results | Where-Object { $_.Required -and $_.Status -eq 'FAIL' }).Count -gt 0) { return 1 }
    if (@($Results | Where-Object { $_.Status -ne 'PASS' }).Count -gt 0) { return 2 }
    return 0
}
Export-ModuleMember -Function Initialize-Probe, Get-PreflightTargets, Get-EndpointStatus, Get-PreflightExitCode
