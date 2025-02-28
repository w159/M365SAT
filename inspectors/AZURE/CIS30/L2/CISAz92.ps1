# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz92
{
    param (
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{ 
        UUID             = "CISAz92"
        ID               = "9.2"
        Title            = "(L2) Ensure App Service Authentication is set up for apps in Azure App Service"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "By default, App Service Authentication is disabled"
        ExpectedValue    = "App Service Authentication is enabled"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "By enabling App Service Authentication, every incoming HTTP request passes through it before being handled by the application code. It also handles authentication of users with the specified provider (Entra ID, Facebook, Google, Microsoft Account, and Twitter), validation, storing and refreshing of tokens, managing the authenticated sessions, and injecting identity information into request headers. Disabling HTTP Basic Authentication functionality further ensures legacy authentication methods are disabled within the application."
        Impact           = "This is only required for App Services which require authentication. Enabling on site like a marketing or support website will prevent unauthenticated access which would be undesirable. Adding Authentication requirement will increase cost of App Service and require additional security components to facilitate the authentication."
        Remediation      = "Use the following PowerShell command to enable App Service Authentication: Set-AzWebApp -ResourceGroupName <RESOURCE_GROUP_NAME> -Name <APP_NAME> -HttpsOnly $true -Enabled $true"
        References       = @(
            @{ 'Name' = 'Authentication and authorization in Azure App Service and Azure Functions'; 'URL' = 'https://learn.microsoft.com/en-us/azure/app-service/overview-authentication-authorization' },
            @{ 'Name' = 'Website Contributor'; 'URL' = 'https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/web-and-mobile#website-contributor' },
            @{ 'Name' = 'PA-3: Manage lifecycle of identities and entitlements'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-access#pa-3-manage-lifecycle-of-identities-and-entitlements' },
            @{ 'Name' = 'GS-6: Define and implement identity and privileged access strategy'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-strategy#gs-6-define-and-implement-identity-and-privileged-access-strategy' }
        )
    }

    return $inspectorobject
}


function Audit-CISAz92
{
    try
    {
        # Checking for Web Apps where App Service Authentication is not enabled
        $Violation = @()
        $WebApps = Get-AzWebApp -ProgressAction SilentlyContinue

        foreach ($WebApp in $WebApps)
        {
            $App = Get-AzWebApp -ResourceGroupName $WebApp.ResourceGroup -Name $WebApp.Name -ProgressAction SilentlyContinue
            
            if ($App.Enabled -ne $true)
            {
                $Violation += $WebApp.DefaultHostName
            }
        }

        if ($Violation.Count -gt 0)
        {
            $FinalObject = Build-CISAz92 -ReturnedValue $Violation -Status "FAIL" -RiskScore "0" -RiskRating "Informational"
            return $FinalObject
        }
        else
        {
            $FinalObject = Build-CISAz92 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz92 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz92
