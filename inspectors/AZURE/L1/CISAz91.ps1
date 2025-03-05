# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz91
{
    param (
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{ 
        UUID             = "CISAz91"
        ID               = "9.1"
        Title            = "(L1) Ensure 'HTTPS Only' is set to 'On'"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "HTTPS-only Feature is disabled"
        ExpectedValue    = "HTTPS-only Feature is enabled"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Enabling HTTPS-only traffic will redirect all non-secure HTTP requests to HTTPS ports. HTTPS uses the TLS/SSL protocol to provide a secure connection which is both encrypted and authenticated. It is therefore important to support HTTPS for the security benefits."
        Impact           = "When it is enabled, every incoming HTTP request is redirected to the HTTPS port. This means an extra level of security will be added to the HTTP requests made to the app."
        Remediation      = 'Use the following PowerShell script to remediate the issue: Set-AzWebApp -ResourceGroupName <RESOURCE_GROUP_NAME> -Name <APP_NAME> -HttpsOnly $true'
        References       = @(
            @{ 'Name' = 'HTTPS and Certificates'; 'URL' = 'https://learn.microsoft.com/en-us/azure/app-service/overview-security?source=recommendations#https-and-certificates' },
            @{ 'Name' = 'DP-3: Encrypt sensitive data in transit'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-data-protection#dp-3-encrypt-sensitive-data-in-transit' },
            @{ 'Name' = 'Enable HTTPS setting on Azure App service using Azure policy'; 'URL' = 'https://techcommunity.microsoft.com/t5/azure-paas-blog/enable-https-setting-on-azure-app-service-using-azure-policy/ba-p/3286603' }
        )
    }

    return $inspectorobject
}


function Audit-CISAz91
{
    try
    {
        # Checking for Web Apps where HTTPS-only is not enabled
        $Violation = @()
        $WebApps = Get-AzWebApp -ProgressAction SilentlyContinue

        foreach ($WebApp in $WebApps)
        {
            if ($WebApp.HttpsOnly -ne $true)
            {
                $Violation += $WebApp.DefaultHostName
            }
        }

        if ($Violation.Count -gt 0)
        {
            $FinalObject = Build-CISAz91 -ReturnedValue $Violation -Status "FAIL" -RiskScore "6" -RiskRating "Medium"
            return $FinalObject
        }
        else
        {
            $FinalObject = Build-CISAz91 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz91 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz91
