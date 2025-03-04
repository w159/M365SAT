# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMEx2113
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMEx2113"
        ID               = "2.1.13"
        Title            = "(L1) Ensure the Connection Filter Safe List is Off"
        ProductFamily    = "Microsoft Exchange"
        DefaultValue     = "EnableSafeList : False"
        ExpectedValue    = "EnableSafeList : False"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Allow-listing email addresses or domains without additional verification such as mail flow rules bypasses essential spam filtering and sender authentication (SPF, DKIM, DMARC). This increases the risk of attackers successfully delivering malicious emails to the inbox. Attackers could exploit this method to send malware or phishing emails that would otherwise be detected and filtered."
        Impact           = "This is the default behavior. IP Allow lists may reduce false positives, however, this benefit is outweighed by the importance of a policy which scans all messages regardless of the origin. This supports the principle of zero trust."
        Remediation		 = 'Set-HostedConnectionFilterPolicy -Identity Default -EnableSafeList $false'
        References       = @(
            @{ 'Name' = 'Configure connection filtering'; 'URL' = "https://learn.microsoft.com/en-us/defender-office-365/connection-filter-policies-configure" },
            @{ 'Name' = 'Use the IP Allow List'; 'URL' = "https://learn.microsoft.com/en-us/defender-office-365/create-safe-sender-lists-in-office-365#use-the-ip-allow-list" },
            @{ 'Name' = 'User and tenant settings conflict'; 'URL' = "https://learn.microsoft.com/en-us/defender-office-365/how-policies-and-protections-are-combined#user-and-tenant-settings-conflict" }
        )
    }
    return $inspectorobject
}

function Inspect-CISMEx2113
{	
	Try
	{
		$HostedConnectionFilterPolicy = Get-HostedConnectionFilterPolicy -Identity Default
		
		If ($HostedConnectionFilterPolicy.EnableSafeList -eq $true)
		{
			$HostedConnectionFilterPolicy | Format-Table -AutoSize | Out-File "$path\CISMEx2113-HostedConnectionFilterPolicy.txt"
			$endobject = Build-CISMEx2113 -ReturnedValue $HostedConnectionFilterPolicy -Status "FAIL" -RiskScore "9" -RiskRating "Medium"
			Return $endobject
		}
		else
		{
			$endobject = Build-CISMEx2113 -ReturnedValue $HostedConnectionFilterPolicy -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMEx2113 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
	
}

return Inspect-CISMEx2113


