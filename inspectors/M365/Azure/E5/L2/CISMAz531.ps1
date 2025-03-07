# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMAz531
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMAz531"
        ID               = "5.3.1"
        Title            = "(L2) Ensure 'Privileged Identity Management' is used to manage roles"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "No Policy"
        ExpectedValue    = "A Correctly Configured Policy"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Privileged Identity Management (PIM) helps organizations minimize the number of people who have access to sensitive resources while still allowing necessary privileged operations. PIM enables just-in-time (JIT) privileged access to roles, ensuring oversight of administrator actions to mitigate the risk of excessive, unnecessary, or misused access rights."
        Impact           = "Implementation of Just in Time privileged access is likely to necessitate changes to administrator routine. Administrators will only be granted access to administrative roles when required. When administrators request role activation, they will need to document the reason for requiring role access, anticipated time required to have the access, and to reauthenticate to enable role access."
        Remediation 	 = 'https://entra.microsoft.com/#view/Microsoft_Azure_PIMCommon/ResourceMenuBlade/~/quickstart/resourceId//resourceType/tenant/provider/aadroles'
        References       = @(
            @{ 'Name' = 'What is Microsoft Entra Privileged Identity Management?'; 'URL' = 'https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure' }
        )
    }
    return $inspectorobject
}

function Audit-CISMAz531
{
	try
	{
		# Actual Script
		$Violation = @()
		$Subscriptions = (Get-MgSubscribedSku).ServicePlans | Where-Object { $_.ServicePlanName -Like 'AAD_PREMIUM*' }
		foreach ($Subscription in $Subscriptions)
		{
			if ($Subscription.ServicePlanName -ne "AAD_PREMIUM_P2")
			{
				$Violation += "Privileged Identity Management can't be used, because no P2 License is assigned!"
			}
			else
			{
				$Violation += "Please manually check if Priviledged Identity Management is enabled."
			}
		}
		
		# Validation
		if ($Violation.Count -ne 0)
		{
			$Violation | Format-Table -AutoSize | Out-File "$path\CISMAz531-Subscriptions.txt"
			$endobject = Build-CISMAz531 -ReturnedValue ($Violation) -Status "FAIL" -RiskScore "5" -RiskRating "Medium"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMAz531 -ReturnedValue "Privileged Identity Management is Configured" -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMAz531 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMAz531