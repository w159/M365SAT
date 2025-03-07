# Benchmark: CIS Microsoft Azure v3.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz2021
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz2021"
        ID               = "2.21"
        Title            = "(L2) Ensure that 'Users can create Microsoft 365 groups in Azure portals, API or PowerShell' is set to 'No"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "True"
        ExpectedValue    = "False"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "By default, any user in the organization can create a Microsoft 365 group. This can lead to uncontrolled group sprawl and potential security risks. Restricting Microsoft 365 group creation to administrators ensures that groups are properly managed and comply with organizational policies."
        Impact           = "Enabling this setting could create a number of requests that would need to be managed by an administrator."
        Remediation      = 'To restrict Microsoft 365 group creation to administrators, run the followin PowerShell Command: $params = @{ Values = @(@{ Name = "EnableGroupCreation"; Value = "False" }) }; Update-MgDirectorySetting -DirectorySettingId $directorySettingId -BodyParameter $params'
        References       = @(
            @{ 'Name' = 'How to disable Microsoft 365 Group creation'; 'URL' = 'https://whitepages.bifocal.show/2017/01/disable-office-365-groups-2/' },
            @{ 'Name' = 'PA-1: Separate and limit highly privileged/administrative users'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-privileged-access#pa-1-separate-and-limit-highly-privilegedadministrative-users' },
            @{ 'Name' = 'PA-3: Manage lifecycle of identities and entitlements'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-access#pa-3-manage-lifecycle-of-identities-and-entitlements' },
            @{ 'Name' = 'GS-2: Define and implement enterprise segmentation/separation of duties strategy'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-governance-strategy#gs-2-define-and-implement-enterprise-segmentationseparation-of-duties-strategy' },
            @{ 'Name' = 'GS-6: Define and implement identity and privileged access strategy'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-governance-strategy#gs-6-define-and-implement-identity-and-privileged-access-strategy' }
        )
    }
    return $inspectorobject
}

function Audit-CISAz2021
{
	try
	{
		$AffectedObject = @()
		# Actual Script
		$BetaSettings = (Invoke-MgGraphRequest -Method GET "https://graph.microsoft.com/beta/settings")
		$hash = $BetaSettings.value.values
		$BetaSettingsObject = [PSCustomObject]@{ } #Create Custom Object
		# Convert HashTable names to name and assign value to it so we can correctly make the CustomObject
		foreach ($h in $hash.GetEnumerator())
		{
			$BetaSettingsObject | Add-Member -MemberType NoteProperty -Name $h.Name -Value $h.Value
		}
		
		# Validation
		if ($BetaSettingsObject.EnableGroupCreation -eq $true)
		{
			$endobject = Build-CISAz2021 -ReturnedValue ("EnableGroupCreation: $($BetaSettingsObject.EnableGroupCreation)") -Status "FAIL" -RiskScore "15" -RiskRating "High"
			return $endobject
		}
		else
		{
			$endobject = Build-CISAz2021 -ReturnedValue "Users cannot create Microsoft 365 groups in Azure portals, API or PowerShell" -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISAz2021 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISAz2021