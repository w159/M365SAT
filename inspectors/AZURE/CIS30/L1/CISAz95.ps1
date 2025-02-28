# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz95
{
    param (
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{ 
        UUID             = "CISAz95"
        ID               = "9.5"
        Title            = "(L1) Ensure that Register with Entra ID is enabled on App Service"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "By default, Managed service identity via Entra ID is disabled."
        ExpectedValue    = "Enabled"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "App Service provides a highly scalable, self-patching web hosting service in Azure. It also provides a managed identity for apps, which is a turn-key solution for securing access to Azure SQL Database and other Azure services."
        Impact           = "Failure to enable managed identity may lead to security risks by requiring apps to use hardcoded credentials instead of secure identity-based authentication."
        Remediation      = 'Use the following PowerShell script to enable managed identity: Set-AzWebApp -AssignIdentity $True -ResourceGroupName <Resource_Group_Name> -Name <App_Name>'
        References       = @(
            @{ 'Name' = 'Tutorial: Connect to SQL Database from .NET App Service without secrets using a managed identity'; 'URL' = 'https://learn.microsoft.com/en-gb/azure/app-service/tutorial-connect-msi-sql-database?tabs=windowsclient%2Cefcore%2Cdotnet' },
            @{ 'Name' = 'IM-1: Use centralized identity and authentication system'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-identity-management#im-1-use-centralized-identity-and-authentication-system' }
        )
    }

    return $inspectorobject
}


function Audit-CISAz95
{
    try
    {
        # Checking for web apps where Managed Identity is not enabled
        $Violation = @()
        $WebApps = Get-AzWebApp -ProgressAction SilentlyContinue

        foreach ($WebApp in $WebApps)
        {
            $AppIdentity = (Get-AzWebApp -ResourceGroupName $WebApp.ResourceGroup -Name $WebApp.Name -ProgressAction SilentlyContinue).Identity.PrincipalId
            
            if ($null -eq $AppIdentity)
            {
                $Violation += $WebApp.DefaultHostName
            }
        }

        if ($Violation.Count -gt 0)
        {
            $FinalObject = Build-CISAz95 -ReturnedValue $Violation -Status "FAIL" -RiskScore "4" -RiskRating "Medium"
            return $FinalObject
        }
        else
        {
            $FinalObject = Build-CISAz95 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz95 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz95
