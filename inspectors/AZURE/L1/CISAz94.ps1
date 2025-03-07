# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz94
{
    param (
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{ 
        UUID             = "CISAz94"
        ID               = "9.4"
        Title            = "(L1) Ensure Web App is using the latest version of TLS encryption"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "1.2"
        ExpectedValue    = "1.2"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "App Service currently allows web apps to set TLS versions 1.0, 1.1, and 1.2. It is highly recommended to use the latest TLS 1.2 version for secure web app connections."
        Impact           = "Failure to enforce TLS 1.2 may expose web applications to security vulnerabilities associated with older TLS versions."
        Remediation      = "Use the following PowerShell command to enforce TLS 1.2: Set-AzWebApp -ResourceGroupName <RESOURCE_GROUP_NAME> -Name <APP_NAME> -MinTlsVersion 1.2"
        References       = @(
            @{ 'Name' = 'Provide security for a custom DNS name with a TLS/SSL binding in App Service'; 'URL' = 'https://learn.microsoft.com/en-us/azure/app-service/configure-ssl-bindings#enforce-tls-versions' },
            @{ 'Name' = 'DP-3: Encrypt sensitive data in transit'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-data-protection#dp-3-encrypt-sensitive-data-in-transit' },
            @{ 'Name' = 'NS-8: Detect and disable insecure services and protocols'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-network-security#ns-8-detect-and-disable-insecure-services-and-protocols' }
        )
    }

    return $inspectorobject
}


function Audit-CISAz94
{
    try
    {
        # Checking for Web Apps that are not using TLS 1.2
        $Violation = @()
        $WebApps = Get-AzWebApp -ProgressAction SilentlyContinue

        foreach ($WebApp in $WebApps)
        {
            $App = (Get-AzWebApp -ResourceGroupName $WebApp.ResourceGroup -Name $WebApp.Name -ProgressAction SilentlyContinue).SiteConfig.MinTlsVersion
            if ($App -ne "1.2")
            {
                $Violation += $WebApp.DefaultHostName
            }
        }

        if ($Violation.Count -gt 0)
        {
            $FinalObject = Build-CISAz94 -ReturnedValue $Violation -Status "FAIL" -RiskScore "3" -RiskRating "Low"
            return $FinalObject
        }
        else
        {
            $FinalObject = Build-CISAz94 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz94 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz94
