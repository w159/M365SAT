#Requires -module Az.Accounts
# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMAz5233
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMAz5233"
        ID               = "5.2.3.3"
        Title            = "(L1) Ensure password protection is enabled for on-prem Active Directory"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "Enable - Yes \n Mode - Audit"
        ExpectedValue    = "Enable - Yes \n Mode - Enforced"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "This feature protects an organization by prohibiting the use of weak or leaked passwords. In addition, organizations can create custom banned password lists to prevent their users from using easily guessed passwords that are specific to their industry. Deploying this feature to Active Directory will strengthen the passwords that are used in the environment."
        Impact           = "The potential impact associated with implementation of this setting is dependent upon the existing password policies in place in the environment. For environments that have strong password policies in place, the impact will be minimal. For organizations that do not have strong password policies in place, implementation of Microsoft Entra Password Protection may require users to change passwords and adhere to more stringent requirements than they have been accustomed to."
        Remediation  	 = 'https://portal.azure.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/PasswordProtection'
        References       = @(
            @{ 'Name' = 'Enable on-premises Microsoft Entra Password Protection'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-ban-bad-on-premises-operations' }
        )
    }
    return $inspectorobject
}

function Audit-CISMAz5233
{
	try
	{
		$AffectedOptions = @()
		# Actual Script
		$MethodsRequired = @{}

		$Request = ((Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/groupSettings").value | Where-Object { $_.displayName -eq "Password Rule Settings" }).values 
		$Request | ForEach-Object {
			$MethodsRequired[$_.Name] = $_.Value
		}

		$MethodsRequired = [PSCustomObject]$MethodsRequired

		# Validation
		if ($MethodsRequired.bannedPasswordCheckOnPremisesMode -ne 'Enforced')
		{
			$AffectedOptions += "PolicyMode: $($MethodsRequired.bannedPasswordCheckOnPremisesMode)"
		}
		if ($MethodsRequired.enableBannedPasswordCheckOnPremises -eq $false)
		{
			$AffectedOptions += "Password protection for Windows Server Active Directory: $($MethodsRequired.enableBannedPasswordCheckOnPremises)"
		}
		if ($AffectedOptions.count -igt 0)
		{
			$AffectedOptions | Format-Table -AutoSize | Out-File "$path\CISMAz5233-PasswordPolicy.txt"
			$endobject = Build-CISMAz5233 -ReturnedValue ($AffectedOptions) -Status "FAIL" -RiskScore "5" -RiskRating "Medium"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMAz5233 -ReturnedValue "All Settings are Enabled and correctly configured!" -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMAz5233 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}

return Audit-CISMAz5233