# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMAz5181
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMAz5181"
        ID               = "5.1.8.1"
        Title            = "(L1) Ensure that password hash sync is enabled for hybrid deployments"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "False"
        ExpectedValue    = "False"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Password hash synchronization helps by reducing the number of passwords your users need to maintain to just one and enables leaked credential detection for your hybrid accounts. Using other options for directory synchronization may be less resilient, as Microsoft can still process sign-ins to 365 with Hash Sync even if a network connection to your on-premises environment is unavailable."
        Impact           = "Compliance or regulatory restrictions may exist, depending on the organization's business sector, that preclude hashed versions of passwords from being securely transmitted to cloud data centers."
        Remediation 	 = 'https://stackoverflow.com/questions/62036670/is-there-any-ps-command-to-disable-password-hash-sync'
        References       = @(
            @{ 'Name' = 'What is password hash synchronization with Microsoft Entra ID?'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/whatis-phs' },
            @{ 'Name' = 'What are risk detections?'; 'URL' = 'https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks#user-linked-detections' }
        )
    }
    return $inspectorobject
}

Function Audit-CISMAz5181
{
	Try
	{
		
		$OnPremiseSyncEnabledCheck = Get-MgOrganization | Select-Object OnPremisesSyncEnabled
		if ($OnPremiseSyncEnabledCheck.OnPremisesSyncEnabled -ne $true)
		{
			$OnPremiseSyncEnabledCheck | Format-Table -AutoSize | Out-File "$path\CISMAz5181-OnPremiseSyncEnabledCheck.txt"
			$endobject = Build-CISMAz5181 -ReturnedValue ($OnPremiseSyncEnabledCheck.OnPremisesSyncEnabled) -Status "FAIL" -RiskScore "10" -RiskRating "High"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMAz5181 -ReturnedValue ($OnPremiseSyncEnabledCheck.OnPremisesSyncEnabled) -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMAz5181 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}

Return Audit-CISMAz5181


