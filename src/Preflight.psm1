Set-StrictMode -Version 2.0
function Initialize-Probe {
    if (-not ('FalconPreflight.NetworkProbe' -as [type])) {
        Add-Type -Path (Join-Path $PSScriptRoot 'NetworkProbe.cs')
    }
}
function Get-PreflightTargets {
    param([string]$Cloud, [switch]$IncludeConsole, [string[]]$AdditionalHost)
    $suffixes = @{ 'US-1' = 'b'; 'US-2' = 'gyr-maverick'; 'EU-1' = 'lanner-lion' }
    if (-not $suffixes.ContainsKey($Cloud)) { throw "Unsupported cloud: $Cloud" }
    foreach ($prefix in @('ts01', 'lfodown01', 'lfoup01')) {
        [pscustomobject]@{ Hostname = "$prefix-$($suffixes[$Cloud]).cloudsink.net"; Required = $true; Category = 'Sensor' }
    }
    if ($IncludeConsole) {
        $domain = switch ($Cloud) { 'US-1' { 'crowdstrike.com' }; 'US-2' { 'us-2.crowdstrike.com' }; 'EU-1' { 'eu-1.crowdstrike.com' } }
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
