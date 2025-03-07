# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMEx136
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    #Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMEx136"
        ID               = "1.3.6"
        Title            = "(L2) Ensure the customer lockbox feature is enabled"
        ProductFamily    = "Microsoft Exchange"
        DefaultValue     = "False"
        ExpectedValue    = "True"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Customer Lockbox is a security feature that adds an additional layer of control and transparency over customer data in Microsoft 365. It introduces an approval process for Microsoft support personnel accessing organizational data, ensuring an audited trail for compliance requirements. Enabling this feature protects against potential data spillage and exfiltration."
        Impact           = "Without Customer Lockbox enabled, Microsoft support personnel may access your organization's data without explicit approval, potentially compromising data privacy and compliance."
        Remediation      = 'Set-OrganizationConfig -CustomerLockBoxEnabled $true'
        References       = @(
            @{ 'Name' = 'Customer Lockbox Overview'; 'URL' = 'https://learn.microsoft.com/en-us/azure/security/fundamentals/customer-lockbox-overview' }
        )
    }
    return $inspectorobject
}

function Build-CISMEx136($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMEx136"
		FindingName	     = "CIS MEx 1.3.6 - CustomerLockbox Feature is disabled"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "10"
		Description	     = "Customer Lockbox is a security feature that provides an additional layer of control and transparency to customer data in Microsoft 365. It offers an approval process for Microsoft support personnel to access organization data and creates an audited trail to meet compliance requirements. Enabling this feature protects organizational data against data spillage and exfiltration."
		Remediation	     = "Use the PowerShell script to enable CustomerLockBox for your Exchange Tenant"
		PowerShellScript = 
		DefaultValue	 = "False"
		ExpectedValue    = "True"
		ReturnedValue    = $findings
		Impact		     = "2"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Customer Lockbox Overview'; 'URL' = "https://learn.microsoft.com/en-us/azure/security/fundamentals/customer-lockbox-overview" })
	}
	return $inspectorobject
}

function Audit-CISMEx136
{
	try
	{
		$CustomerLockbox = Get-OrganizationConfig | Select-Object CustomerLockBoxEnabled
		
		if ($CustomerLockbox.CustomerLockBoxEnabled -match 'False')
		{
			$CustomerLockbox | Format-Table -AutoSize | Out-File "$path\CISMEx136-CustomerLockBoxSetting.txt"
			$endobject = Build-CISMEx136 -ReturnedValue ('CustomerLockBoxEnabled: ' + $CustomerLockbox.CustomerLockBoxEnabled) -Status "FAIL" -RiskScore "10" -RiskRating "High"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMOff136 -ReturnedValue ('CustomerLockBoxEnabled: ' + $CustomerLockbox.CustomerLockBoxEnabled) -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
	}
	catch
	{
		$endobject = Build-CISMOff135 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMEx136