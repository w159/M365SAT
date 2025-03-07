# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMEx2110
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMEx2110"
        ID               = "2.1.10"
        Title            = "(L1) Ensure DMARC Records for all Exchange Online domains are published"
        ProductFamily    = "Microsoft Exchange"
        DefaultValue     = "False for all custom domains"
        ExpectedValue    = "Published DMARC record"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Domain-based Message Authentication, Reporting, and Conformance (DMARC) enhances email security by working in conjunction with SPF and DKIM to verify the legitimacy of email senders. Implementing DMARC allows for the validation of email sources, thereby reducing the risk of email spoofing and improving domain reputation. Without DMARC, there is a higher risk of email spoofing, phishing attacks, and unauthorized use of your domain, leading to potential security breaches and reputational damage."
        Impact           = "There should be no impact of setting up DMARC however, organizations should ensure appropriate setup to ensure continuous mail-flow."
        Remediation      = "Before implementing DMARC, ensure that SPF and DKIM are properly configured, as DMARC relies on them. Review the organization's current email authentication setup and, if ready, proceed with DMARC implementation by following the steps outlined in the provided references."
        References       = @(
            @{ 'Name' = 'Use DMARC to validate email'; 'URL' = 'https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/use-dmarc-to-validate-email?view=o365-worldwide' },
            @{ 'Name' = 'DMARC Overview, Anatomy of a DMARC Record, How Senders Deploy DMARC in 5 Steps'; 'URL' = 'https://dmarc.org/overview/' },
            @{ 'Name' = 'What is a DMARC record?'; 'URL' = 'https://mxtoolbox.com/dmarc/details/what-is-a-dmarc-record' },
            @{ 'Name' = 'DMARC Configuration'; 'URL' = 'https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/email-authentication-dmarc-configure?view=o365-worldwide' }
        )
    }
    return $inspectorobject
}

function Inspect-CISMEx2110
{	
	Try
	{
		if ($PSVersionTable.PSVersion.Major -eq 7){
			if($IsLinux){
				$domains = (Get-AcceptedDomain).DomainName
				$domains_without_records = @()
				ForEach ($domain in $domains)
				{
					try
					{
						$dmarc_record = (host -t txt $domain) | where-object {$_ -match "v=DMARC1" -and $_ -match "pct=100" -and $_ -match "rua=mailto:" -and $_ -match "ruf=mailto:" -and ($_ -match "p=reject" -or $_ -match "p=quarantine")}
						if ([string]::IsNullOrEmpty($dmarc_record) -eq $true)
						{
							$domains_without_records += $domain
						}
					}
					catch
					{
						$domains_without_records += $domain
					}
				}
			}
			else{
				$domains = (Get-AcceptedDomain).DomainName
				$domains_without_records = @()
				
				ForEach ($domain in $domains)
				{
					try
					{
						$dmarc_record = (Resolve-DnsName -Name $domain -Type TXT | where-object {$_ -match "v=DMARC1" -and $_ -match "pct=100" -and $_ -match "rua=mailto:" -and $_ -match "ruf=mailto:" -and ($_ -match "p=reject" -or $_ -match "p=quarantine")}).Strings
						if ([string]::IsNullOrEmpty($dmarc_record) -eq $true)
						{
							$domains_without_records += $domain
						}
					}
					catch
					{
						$domains_without_records += $domain
					}
				}
			}
		}else{
			$domains = (Get-AcceptedDomain).DomainName
			$domains_without_records = @()
			
			ForEach ($domain in $domains)
			{
				try
				{
					$dmarc_record = (Resolve-DnsName -Name $domain -Type TXT | where-object {$_ -match "v=DMARC1" -and $_ -match "pct=100" -and $_ -match "rua=mailto:" -and $_ -match "ruf=mailto:" -and ($_ -match "p=reject" -or $_ -match "p=quarantine")}).Strings					
					if ([string]::IsNullOrEmpty($dmarc_record) -eq $true)
					{
						$domains_without_records += $domain
					}
				}
				catch
				{
					$domains_without_records += $domain
				}
			}
		}
		
		If ($domains_without_records.Count -ne 0)
		{
			$domains_without_records | Format-Table -AutoSize | Out-File "$path\CISMEx2110-DomainsWithoutDMARC.txt"
			$endobject = Build-CISMEx2110 -ReturnedValue $domains_without_records -Status "FAIL" -RiskScore "9" -RiskRating "Medium"
			Return $endobject
		}
		else
		{
			$endobject = Build-CISMEx2110 -ReturnedValue $domains -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMEx2110 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
	
}

return Inspect-CISMEx2110


