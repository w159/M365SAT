# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMSp733
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMSp733"
        ID               = "7.3.3"
        Title            = "(L1) Ensure custom script execution is restricted on personal sites"
        ProductFamily    = "Microsoft SharePoint"
        DefaultValue     = "Prevent users from running custom script on personal sites, Prevent users from running custom script on self-service created sites"
        ExpectedValue    = "True"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Custom scripts could contain malicious instructions unknown to the user or administrator. Allowing users to run custom scripts reduces the organization's ability to enforce governance, scope the capabilities of inserted code, block specific parts of code, or prevent deployment of potentially harmful custom code."
        Impact           = "Permitting custom script execution can lead to unregulated deployment of harmful code and compromise security."
        Remediation = @'
Get-SPOSite | Set-SPOSite -DenyAddAndCustomizePages 1
Get-PnPSite | Set-PnPSite -NoScriptSite $true
'@
        References       = @(
            @{ 'Name' = 'Security considerations of allowing custom script'; 'URL' = 'https://learn.microsoft.com/en-us/sharepoint/security-considerations-of-allowing-custom-script' },
            @{ 'Name' = 'Allow or prevent custom script'; 'URL' = 'https://learn.microsoft.com/en-us/sharepoint/allow-or-prevent-custom-script' }
        )
    }
    return $inspectorobject
}

function Audit-CISMSp733
{
	try
	{
		$Module = Get-Module PnP.PowerShell -ListAvailable
		if(-not [string]::IsNullOrEmpty($Module))
		{
			$DNAIFSP = Get-PnPTenant
			if ($DNAIFSP.DelayDenyAddAndCustomizePagesEnforcement -ne $true)
			{
				$DNAIFSP | Format-Table -AutoSize | Out-File "$path\CISMSp732-PnPTenant.txt"
				$endobject = Build-CISMSp733 -ReturnedValue ("DelayDenyAddAndCustomizePagesEnforcement: $($DNAIFSP.DelayDenyAddAndCustomizePagesEnforcement)") -Status "FAIL" -RiskScore "0" -RiskRating "Informational"
				return $endobject
			}
			else
			{
				$endobject = Build-CISMSp733 -ReturnedValue ("DelayDenyAddAndCustomizePagesEnforcement: $($DNAIFSP.DelayDenyAddAndCustomizePagesEnforcement)") -Status "PASS" -RiskScore "0" -RiskRating "None"
				Return $endobject
			}
			return $null
		}
		else
		{
			$DNAIFSP = Get-SPOTenant
			if ($DNAIFSP.DelayDenyAddAndCustomizePagesEnforcement -ne $true)
			{
				$DNAIFSP | Format-Table -AutoSize | Out-File "$path\CISMSp732-SPOTenant.txt"
				$endobject = Build-CISMSp733 -ReturnedValue ("DelayDenyAddAndCustomizePagesEnforcement: $($DNAIFSP.DelayDenyAddAndCustomizePagesEnforcement)") -Status "FAIL" -RiskScore "0" -RiskRating "Informational"
				return $endobject
			}
			else
			{
				$endobject = Build-CISMSp733 -ReturnedValue ("DelayDenyAddAndCustomizePagesEnforcement: $($DNAIFSP.DelayDenyAddAndCustomizePagesEnforcement)") -Status "PASS" -RiskScore "0" -RiskRating "None"
				Return $endobject
			}
			return $null
		}
	}
	catch
	{
		$endobject = Build-CISMSp733 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMSp733