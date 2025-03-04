# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMEx211
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    #Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMEx211"
        ID               = "2.1.1"
        Title            = "(L2) Ensure Safe Links for Office Applications is Enabled"
        ProductFamily    = "Microsoft Exchange"
        DefaultValue     = "Undefined"
        ExpectedValue    = "EnableSafeLinksForEmail: True EnableSafeLinksForTeams: True EnableSafeLinksForOffice: True TrackClicks: True AllowClickThrough: False ScanUrls: True EnableForInternalSenders: True DeliverMessageAfterScan: True DisableUrlRewrite: False"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Enabling a Safe Links policy for Office applications ensures that URLs within Office documents and email applications are verified and rewritten if necessary using Defender for Office's time-of-click protection. This policy extends phishing protection to hyperlinks in documents and emails, even after delivery."
        Impact           = "User impact associated with this change is minor - users may experience a very short delay when clicking on URLs in Office documents before being directed to the requested site. Users should be informed of the change as, in the event a link is unsafe and blocked, they will receive a message that it has been blocked."
        Remediation      = '$params = @{ Name = "CIS SafeLinks Policy" EnableSafeLinksForEmail = $true EnableSafeLinksForTeams = $true EnableSafeLinksForOffice = $true TrackClicks = $true AllowClickThrough = $false ScanUrls = $true EnableForInternalSenders = $true DeliverMessageAfterScan = $true DisableUrlRewrite = $false }; New-SafeLinksPolicy @params ; New-SafeLinksRule -Name "CIS SafeLinks" -SafeLinksPolicy "CIS SafeLinks Policy" -RecipientDomainIs (Get-AcceptedDomain).Name -Priority 0 '
        References       = @(
            @{ 'Name' = 'SafeLinks Policy Configuration'; 'URL' = 'https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/safe-links-policies-configure?view=o365-worldwide' },
            @{ 'Name' = 'Preset Security Policies'; 'URL' = 'https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/preset-security-policies?view=o365-worldwide' }
        )
    }
    return $inspectorobject
}

function Audit-CISMEx211
{
	$AffectedSettings = @()
	$CorrectSettings = @()
	try
	{
		# Actual Script
		try
		{
			$Policies = Get-SafeLinksPolicy | Format-Table Name
			foreach($Policy in $Policies)
			{
				$Settings = Get-SafeLinksPolicy -Identity $Policy.Name
				if ($Settings.EnableSafeLinksForEmail -eq $false -or $Settings.EnableSafeLinksForTeams -eq $false -or $Settings.EnableSafeLinksForOffice -eq $false -or $Settings.TrackClicks -eq $false -or $Settings.AllowClickThrough -eq $true -or $Settings.ScanUrls -eq $false -or $Settings.EnableForInternalSenders -eq $false -or $Settings.DeliverMessageAfterScan -eq $false -or $Settings.DisableUrlRewrite -eq $true)
				{
					$AffectedSettings += $Policy.Name
				}
				else 
				{
					$CorrectSettings += $Policy.Name
				}
				if ($Settings.EnableSafeLinksForEmail -eq $false)
				{
					$AffectedSettings += "EnableSafeLinksForEmail: $($Settings.EnableSafeLinksForEmail)"
				}
				else
				{
					$CorrectSettings += "EnableSafeLinksForEmail: $($Settings.EnableSafeLinksForEmail)"
				}
				if ($Settings.EnableSafeLinksForTeams -eq $false)
				{
					$AffectedSettings += "EnableSafeLinksForTeams: $($Settings.EnableSafeLinksForTeams)"
				}
				else
				{
					$CorrectSettings += "EnableSafeLinksForTeams: $($Settings.EnableSafeLinksForTeams)"
				}
				if ($Settings.EnableSafeLinksForOffice -eq $false)
				{
					$AffectedSettings += "EnableSafeLinksForOffice: $($Settings.EnableSafeLinksForOffice)"
				}
				else
				{
					$CorrectSettings += "EnableSafeLinksForOffice: $($Settings.EnableSafeLinksForOffice)"
				}
				if ($Settings.TrackClicks -eq $false)
				{
					$AffectedSettings += "TrackClicks: $($Settings.TrackClicks)"
				}
				else
				{
					$CorrectSettings += "TrackClicks: $($Settings.TrackClicks)"
				}
				if ($Settings.AllowClickThrough -eq $true)
				{
					$AffectedSettings += "AllowClickThrough: $($Settings.AllowClickThrough)"
				}
				else
				{
					$CorrectSettings += "AllowClickThrough: $($Settings.AllowClickThrough)"
				}
				if ($Settings.ScanUrls -eq $false)
				{
					$AffectedSettings += "ScanUrls: $($Settings.ScanUrls)"
				}
				else
				{
					$CorrectSettings += "ScanUrls: $($Settings.ScanUrls)"
				}
				if ($Settings.EnableForInternalSenders -eq $false)
				{
					$AffectedSettings += "EnableForInternalSenders: $($Settings.EnableForInternalSenders)"
				}
				else
				{
					$CorrectSettings += "EnableForInternalSenders: $($Settings.EnableForInternalSenders)"
				}
				if ($Settings.DeliverMessageAfterScan -eq $false)
				{
					$AffectedSettings += "DeliverMessageAfterScan: $($Settings.DeliverMessageAfterScan)"
				}
				else
				{
					$CorrectSettings += "DeliverMessageAfterScan: $($Settings.DeliverMessageAfterScan)"
				}
				if ($Settings.DisableUrlRewrite -eq $true)
				{
					$AffectedSettings += "DisableUrlRewrite: $($Settings.DisableUrlRewrite)"
				}
				else
				{
					$CorrectSettings += "DisableUrlRewrite: $($Settings.DisableUrlRewrite)"
				}
			}
		}
		catch
		{
			$AffectedSettings += "Subscription is not Active. Thus SafeLinks is not working"
		}
		
		# Validation
		if ($AffectedSettings.Count -igt 0)
		{
			$endobject = Build-CISMEx211 -ReturnedValue $AffectedSettings -Status "FAIL" -RiskScore "12" -RiskRating "High"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMEx211 -ReturnedValue $CorrectSettings -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMEx211 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMEx211