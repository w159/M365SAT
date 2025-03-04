# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMEx212
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMEx212"
        ID               = "2.1.2"
        Title            = "(L1) Ensure the Common Attachment Types Filter is enabled"
        ProductFamily    = "Microsoft Exchange"
        DefaultValue     = "True"
        ExpectedValue    = "True"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "The Common Attachment Types Filter blocks known and potentially malicious file types from being attached to emails, thereby preventing certain types of malware from entering the organization."
        Impact           = "Blocking common malicious file types should not cause an impact in modern computing environments."
        Remediation      = 'Set-MalwareFilterPolicy -Identity Default -EnableFileFilter $true'
        References       = @(
            @{ 'Name' = 'Anti-Malware Policies Configuration'; 'URL' = 'https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-malware-policies-configure?view=o365-worldwide' }
        )
    }
    return $inspectorobject
}

function Inspect-CISMEx212
{
	Try
	{
		# These file types are from Microsoft's default definition of the common attachment types filter.
		$malwarefilterpolicy = Get-MalwareFilterPolicy
		
		if ($malwarefilterpolicy.EnableFileFilter -eq $False)
		{
			$malwarefilterpolicy | Format-Table -AutoSize | Out-File "$path\CISMEx212-MalwareFilterPolicySettings.txt"
			$endobject = Build-CISMEx212 -ReturnedValue ($malwarefilterpolicy.EnableFileFilter) -Status "FAIL" -RiskScore "3" -RiskRating "Low"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMEx212 -ReturnedValue ($malwarefilterpolicy.EnableFileFilter) -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
		
	}
	catch
	{
		$endobject = Build-CISMEx212 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
	
}

return Inspect-CISMEx212


