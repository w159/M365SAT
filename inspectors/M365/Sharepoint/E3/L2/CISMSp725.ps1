# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMSp725
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMSp725"
        ID               = "7.2.5"
        Title            = "(L2) Ensure that SharePoint guest users cannot share items they don't own"
        ProductFamily    = "Microsoft SharePoint"
        DefaultValue     = "False"
        ExpectedValue    = "True"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "File, folder, or site collection owners should control what external users are shared with to prevent unauthorized disclosures of information. Allowing guest users to resharing content increases the risk of data leakage."
        Impact           = "The impact associated with this change is highly dependent upon current practices. If users do not regularly share with external parties, then minimal impact is likely. However, if users do regularly share with guests/externally, minimum impacts could occur as those external users will be unable to 're-share' content."
        Remediation	 	 = 'Set-SPOTenant -PreventExternalUsersFromResharing $true'
        References       = @(
            @{ 'Name' = 'Manage Sharing Settings for SharePoint and OneDrive'; 'URL' = 'https://docs.microsoft.com/en-us/sharepoint/turn-external-sharing-on-or-off' },
            @{ 'Name' = 'External Sharing Overview'; 'URL' = 'https://learn.microsoft.com/en-us/sharepoint/external-sharing-overview' }
        )
    }
    return $inspectorobject
}

function Audit-CISMSp725
{
	Try
	{
		$Module = Get-Module PnP.PowerShell -ListAvailable
		if(-not [string]::IsNullOrEmpty($Module))
		{
			$SharingCapability = (Get-PnPTenant).SharingCapability
			$PreventExternalUsers = (Get-PnPTenant).PreventExternalUsersFromResharing
			If ($SharingCapability -ne "Disabled")
			{
				If ($PreventExternalUsers -eq $False)
				{
					$SharingCapability | Format-Table -AutoSize | Out-File "$path\CISMSp725-SPOTenant.txt"
					$PreventExternalUsers | Format-Table -AutoSize | Out-File "$path\CISMSp725-SPOTenant.txt" -Append
					$endobject = Build-CISMSp725 -ReturnedValue ("PreventExternalUsersFromResharing: $($PreventExternalUsers)") -Status "FAIL" -RiskScore "20" -RiskRating "Critical"
					return $endobject
				}
				else
				{
					$endobject = Build-CISMSp725 -ReturnedValue ("PreventExternalUsersFromResharing: $($PreventExternalUsers)") -Status "PASS" -RiskScore "0" -RiskRating "None"
					Return $endobject
				}
				return $null
			}
			else
			{
				$endobject = Build-CISMSp725 -ReturnedValue ("SharingCapability: $($SharingCapability)") -Status "PASS" -RiskScore "0" -RiskRating "None"
				Return $endobject
			}
		}
		else
		{
			$SharingCapability = (Get-SPOTenant).SharingCapability
			$PreventExternalUsers = (Get-SPOTenant).PreventExternalUsersFromResharing
			If ($SharingCapability -ne "Disabled")
			{
				If ($PreventExternalUsers -eq $False)
				{
					$SharingCapability | Format-Table -AutoSize | Out-File "$path\CISMSp725-SPOTenant.txt"
					$PreventExternalUsers | Format-Table -AutoSize | Out-File "$path\CISMSp725-SPOTenant.txt" -Append
					$endobject = Build-CISMSp725 -ReturnedValue ("PreventExternalUsersFromResharing: $($PreventExternalUsers)") -Status "FAIL" -RiskScore "20" -RiskRating "Critical"
					return $endobject
				}
				else
				{
					$endobject = Build-CISMSp725 -ReturnedValue ("PreventExternalUsersFromResharing: $($PreventExternalUsers)") -Status "PASS" -RiskScore "0" -RiskRating "None"
					Return $endobject
				}
				return $null
			}
			else
			{
				$endobject = Build-CISMSp725 -ReturnedValue ("SharingCapability: $($SharingCapability)") -Status "PASS" -RiskScore "0" -RiskRating "None"
				Return $endobject
			}
		}
	}
	catch
	{
		$endobject = Build-CISMSp725 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}

return Audit-CISMSp725


