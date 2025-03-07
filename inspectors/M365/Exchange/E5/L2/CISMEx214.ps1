# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMEx214
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMEx214"
        ID               = "2.1.4"
        Title            = "(L2) Ensure Safe Attachments policy is enabled"
        ProductFamily    = "Microsoft Exchange"
        DefaultValue     = "False"
        ExpectedValue    = "True"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Safe Attachments is a security feature that analyzes email attachments for malware before they reach the user's inbox. It uses a secure, cloud-based environment to evaluate attachments, providing a strong defense against new or unknown threats."
        Impact           = "Delivery of email with attachments may be delayed while scanning is occurring."
        Remediation      = '$domains = Get-AcceptedDomain; New-SafeAttachmentPolicy -Name "Safe Attachment Policy" -Enable $true -Redirect $false -RedirectAddress $ITSupportEmail New-SafeAttachmentRule -Name "Safe Attachment Rule" -SafeAttachmentPolicy "Safe Attachment Policy" -RecipientDomainIs $domains[0]'
        References       = @(
            @{ 'Name' = 'Safe Attachments in Microsoft Defender for Office 365'; 'URL' = 'https://learn.microsoft.com/en-us/defender-office-365/safe-attachments-about' },
            @{ 'Name' = 'Set up Safe Attachments Policies in Microsoft Defender for Office 365'; 'URL' = 'https://learn.microsoft.com/en-us/defender-office-365/safe-attachments-policies-configure' }
        )
    }
    return $inspectorobject
}

function Inspect-CISMEx214
{
	$SafeAttachmentsViolation = @()
	Try
	{
		
		# This will throw an error if the environment under test does not have an ATP license,
		# but should still work.
		Try
		{
			try
			{
				$safeattachmentpolicy = Get-SafeAttachmentPolicy
				if ($safeattachmentpolicy.Enable -eq $false)
				{
					$SafeAttachmentsViolation += "Enabled: $($safeattachmentpolicy.Enable)"
				}
			}
			catch
			{
				$SafeAttachmentsViolation += "No SafeAttachmentPolicy Found!"
			}
			
			If ($SafeAttachmentsViolation.count -igt 0)
			{
				$safeattachmentpolicy | Format-Table -AutoSize | Out-File "$path\CISMEx214-SafeAttachmentsPolicySettings.txt"
				$endobject = Build-CISMEx214 -ReturnedValue $SafeAttachmentsViolation -Status "FAIL" -RiskScore "15" -RiskRating "High"
				Return $endobject
			}
			else
			{
				$endobject = Build-CISMEx214 -ReturnedValue $safeattachmentpolicy.Enable -Status "PASS" -RiskScore "0" -RiskRating "None"
				Return $endobject
			}
			return $null
		}
		catch
		{
			$endobject = Build-CISMEx214 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
			return $endobject
		}
		
	}
	catch
	{
		$endobject = Build-CISMEx214 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
	
}

return Inspect-CISMEx214


