# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz93
{
    param (
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{ 
        UUID             = "CISAz93"
        ID               = "9.3"
        Title            = "(L1) Ensure 'FTP State' is set to 'FTPS Only' or 'Disabled'"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "By default, App Service Authentication is disabled."
        ExpectedValue    = "App Service Authentication is enabled."
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "FTP is an unencrypted network protocol that will transmit data - including passwords - in clear-text. The use of this protocol can lead to both data and credential compromise, and can present opportunities for exfiltration, persistence, and lateral movement."
        Impact           = "Any deployment workflows that rely on FTP or FTPs rather than the WebDeploy or HTTPs endpoints may be affected."
        Remediation      = "Use the following PowerShell script to remediate the issue: Set-AzWebApp -ResourceGroupName <resource group name> -Name <app name> -FtpsState <Disabled or FtpsOnly>"
        References       = @(
            @{ 'Name' = 'Deploy your app to Azure App Service using FTP/S'; 'URL' = 'https://learn.microsoft.com/en-us/azure/app-service/deploy-ftp?tabs=portal' },
            @{ 'Name' = 'Security in Azure App Service'; 'URL' = 'https://learn.microsoft.com/en-us/azure/app-service/overview-security' },
            @{ 'Name' = 'DP-3: Encrypt sensitive data in transit'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-data-protection#dp-3-encrypt-sensitive-data-in-transit' },
            @{ 'Name' = 'PV-6: Rapidly and automatically remediate vulnerabilities'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-posture-vulnerability-management#pv-6-rapidly-and-automatically-remediate-vulnerabilities' }
        )
    }

    return $inspectorobject
}


function Audit-CISAz93
{
    try
    {
        # Checking for Web Apps where FTP is not set to 'FTPS Only' or 'Disabled'
        $Violation = @()
        $WebApps = Get-AzWebApp -ProgressAction SilentlyContinue

        foreach ($WebApp in $WebApps)
        {
            $App = Get-AzWebApp -ResourceGroupName $WebApp.ResourceGroup -Name $WebApp.Name -ProgressAction SilentlyContinue | Select-Object -ExpandProperty SiteConfig
            
            if ($App.FtpsState -eq 'AllAllowed')
            {
                $Violation += $WebApp.DefaultHostName
            }
        }

        if ($Violation.Count -gt 0)
        {
            $FinalObject = Build-CISAz93 -ReturnedValue $Violation -Status "FAIL" -RiskScore "3" -RiskRating "Low"
            return $FinalObject
        }
        else
        {
            $FinalObject = Build-CISAz93 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz93 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz93
