# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz96
{
    param (
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz96"
        ID               = "9.6"
        Title            = "(L1) Ensure that 'Basic Authentication' is 'Disabled'"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "Both parameters for Basic Authentication (SCM and FTP) are set to On (True) by default."
        ExpectedValue    = "False"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Basic Authentication introduces an identity silo which can produce privileged access to a resource. This can be exploited in numerous ways and represents a significant vulnerability and attack vector."
        Impact           = "An Identity Provider that can be used by the App Service for authenticating users is required."
        Remediation      = "Select the AppService, Go to Settings > Configuration, Go to General Settings > Toggle both SCM Basic Auth and FTP Basic Auth to 'Off'."
        References       = @(
            @{ 'Name' = 'Disable basic authentication in App Service deployments'; 'URL' = 'https://learn.microsoft.com/en-us/azure/app-service/configure-basic-auth-disable?tabs=portal' }
        )
    }

    return $inspectorobject
}


function Audit-CISAz96
{
    try
    {
        $Violation = @()
        $SubscriptionId = Get-AzContext
        $WebApps = Get-AzWebApp -ProgressAction SilentlyContinue

        foreach ($WebApp in $WebApps)
        {
            $Policy1 = ((Invoke-AzRestMethod "https://management.azure.com/subscriptions/$($SubscriptionId.Subscription.Id)/resourceGroups/$($WebApp.ResourceGroup)/providers/Microsoft.Web/sites/$($WebApp.Name)/basicPublishingCredentialsPolicies/ftp?api-version=2022-03-01").Content | ConvertFrom-Json)
            $Policy2 = ((Invoke-AzRestMethod "https://management.azure.com/subscriptions/$($SubscriptionId.Subscription.Id)/resourceGroups/$($WebApp.ResourceGroup)/providers/Microsoft.Web/sites/$($WebApp.Name)/basicPublishingCredentialsPolicies/scm?api-version=2022-03-01").Content | ConvertFrom-Json)

            if ($Policy1.properties.allow -eq $True)
            {
                $Violation += "$($WebApp.DefaultHostName): FTP Basic Auth Publishing Credentials Enabled"
            }

            if ($Policy2.properties.allow -eq $True)
            {
                $Violation += "$($WebApp.DefaultHostName): SCM Basic Auth Publishing Credentials Enabled"
            }
        }

        if ($Violation.Count -gt 0)
        {
            $FinalObject = Build-CISAz96 -ReturnedValue $Violation -Status "FAIL" -RiskScore "6" -RiskRating "Medium"
            return $FinalObject
        }

        $FinalObject = Build-CISAz96 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
        return $FinalObject
    }
    catch
    {
        $EndObject = Build-CISAz96 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz96
