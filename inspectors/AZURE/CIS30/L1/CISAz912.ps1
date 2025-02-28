# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz912
{
    param (
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz912"
        ID               = "9.12"
        Title            = "(L1) Ensure that 'Remote debugging' is set to 'Off'"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "Disabled"
        ExpectedValue    = "Enabled"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Disabling remote debugging on Azure App Service is primarily about enhancing security. Remote debugging opens a communication channel that can be exploited by attackers. By disabling it, you reduce the number of potential entry points for unauthorized access. If remote debugging is enabled without proper access controls, it can allow unauthorized users to connect to your application, potentially leading to data breaches or malicious code execution. During a remote debugging session, sensitive information might be exposed. Disabling remote debugging helps ensure that such data remains secure. This minimizes the use of remote access tools to reduce risk."
        Impact           = "You will not be able to connect to your application from a remote location to diagnose and fix issues in real-time. You will not be able to step through code, set breakpoints, or inspect variables and the call stack while the application is running on the server. Remote debugging is particularly useful for diagnosing issues that only occur in the production environment. Without it, you will need to rely on logs and other diagnostic tools."
        Remediation      = 'Use the PowerShell script to remediate the issue: Set-AzWebApp -ResourceGroupName <resource_group_name> -Name <app_name> -RemoteDebuggingEnabled $false'
        References       = @(
            @{ 'Name' = 'Remote Debug ASP.NET Core on Azure App Service (Windows)'; 'URL' = 'https://learn.microsoft.com/en-us/visualstudio/debugger/remote-debugging-azure-app-service?view=vs-2022' },
            @{ 'Name' = 'PV-2: Audit and enforce secure configurations'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-posture-vulnerability-management#pv-2-audit-and-enforce-secure-configurations' }
        )
    }

    return $inspectorobject
}


function Audit-CISAz912
{
	try
	{
		$Violation = @()
		$WebApps = Get-AzWebApp -ProgressAction SilentlyContinue
		foreach ($WebApp in $WebApps){
			$App = (Get-AzWebApp -ResourceGroupName $WebApp.ResourceGroup -Name $WebApp.Name -ProgressAction SilentlyContinue).SiteConfig
			if ($App.RemoteDebuggingEnabled -ne $false){
				$Violation += $WebApp.DefaultHostName
			}
		}
		
		
		if ($Violation.Count -gt 0)
        {
            $FinalObject = Build-CISAz912 -ReturnedValue $Violation -Status "FAIL" -RiskScore "0" -RiskRating "Informational"
            return $FinalObject
        }

        $FinalObject = Build-CISAz912 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
        return $FinalObject
    }
    catch
    {
        $EndObject = Build-CISAz912 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz912