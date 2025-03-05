# Benchmark: CIS Microsoft Azure v3.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz212
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz212"
        ID               = "2.1.2"
        Title            = "(L1) Ensure that 'Multi-Factor Auth Status' is 'Enabled' for all Privileged Users"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "All Admins have no MFA Enabled"
        ExpectedValue    = "All Admins have MFA Enabled"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Multi-factor authentication requires an individual to present a minimum of two separate forms of authentication before access is granted. Multi-factor authentication provides additional assurance that the individual attempting to gain access is who they claim to be. With multi-factor authentication, an attacker would need to compromise at least two different authentication mechanisms, increasing the difficulty of compromise and thus reducing the risk."
        Impact           = "Users would require two forms of authentication before any access is granted. Additional administrative time will be required for managing dual forms of authentication when enabling multi-factor authentication."
        Remediation      = "Enable MFA for all Admin users through the Admin Portal. Alternatively, use an appropriate script or automation tool to enforce MFA for privileged accounts."
        References       = @(
            @{ 'Name' = 'How it works: Microsoft Entra multifactor authentication'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-mfa-howitworks' },
            @{ 'Name' = 'Azure Active Directory Premium MFA Attributes via Graph API'; 'URL' = 'https://stackoverflow.com/questions/41156206/azure-active-directory-premium-mfa-attributes-via-graph-api' },
            @{ 'Name' = 'IM-4: Authenticate server and services'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-identity-management#im-4-authenticate-server-and-services' }
        )
    }
    return $inspectorobject
}


function Audit-CISAz212
{
	try
	{
		# Actual Script
		$affectedusers = @()
		$admins = Get-Admins
		
		foreach ($admin in $admins)
		{
			$mfaMethods = Get-MFAMethods -userId $admin
			if ($mfaMethods.status -eq "disabled")
			{
				$affectedusers += $admin
			}
		}

		# Validation
		if ($affectedusers.count -gt 0)
		{
			$SecureDefaultsState | Format-Table -AutoSize | Out-File "$path\CIS112AdminsNonMFA.txt"
			$endobject = Build-CISAz212 -ReturnedValue ($affectedusers.count) -Status "FAIL" -RiskScore "20" -RiskRating "Critical"
			return $endobject
		}
		else
		{
			$endobject = Build-CISAz212 -ReturnedValue ($affectedusers.count) -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISAz212 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}

Function Get-Admins
{
  <#
  .SYNOPSIS
    Get all user with an Admin role
  #>
	process
	{
		$admins = [System.Collections.Generic.List[string]]::new()
		[array]$AdminRoles = Get-MgDirectoryRole | Select-Object DisplayName, Id | Sort-Object DisplayName
		ForEach ($Role in $AdminRoles)
		{
			[array]$RoleMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $Role.Id | Where-Object { $_.AdditionalProperties."@odata.type" -eq "#microsoft.graph.user" }
			ForEach ($Member in $RoleMembers)
			{
				$UserDetails = Get-MgUser -UserId $Member.Id
				$admins.Add($UserDetails.UserPrincipalName)
			}
		}
		return $admins
	}
}



Function Get-MFAMethods
{
  <#
    .SYNOPSIS
      Get the MFA status of the user
  #>
	param (
		[Parameter(Mandatory = $true)]
		$userId
	)
	process
	{
		# Get MFA details for each user
		$mfaData = Get-MgUserAuthenticationMethod -UserId $userId -ErrorAction SilentlyContinue
		
		# Create MFA details object
		$mfaMethods = [PSCustomObject][Ordered]@{
			status		     = "-"
			authApp		     = "-"
			phoneAuth	     = "-"
			fido			 = "-"
			helloForBusiness = "-"
			emailAuth	     = "-"
			tempPass		 = "-"
			passwordLess	 = "-"
			softwareAuth	 = "-"
			authDevice	     = "-"
			authPhoneNr	     = "-"
			SSPREmail	     = "-"
		}
		ForEach ($method in $mfaData)
		{
			if ($method.AdditionalProperties["@odata.type"] -contains "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod")
			{
				# Microsoft Authenticator App
				$mfaMethods.authApp = $true
				$mfaMethods.authDevice = $method.AdditionalProperties["displayName"]
				$mfaMethods.status = "enabled"
			}
			if ($method.AdditionalProperties["@odata.type"] -contains "#microsoft.graph.phoneAuthenticationMethod")
			{
				# Phone authentication
				$mfaMethods.phoneAuth = $true
				$mfaMethods.authPhoneNr = $method.AdditionalProperties["phoneType", "phoneNumber"] -join ' '
				$mfaMethods.status = "enabled"
			}
			if ($method.AdditionalProperties["@odata.type"] -contains "#microsoft.graph.fido2AuthenticationMethod")
			{
				# FIDO2 key
				$mfaMethods.fido = $true
				$fifoDetails = $method.AdditionalProperties["model"]
				$mfaMethods.status = "enabled"
			}
			if ($method.AdditionalProperties["@odata.type"] -contains "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod")
			{
				# Windows Hello
				$mfaMethods.helloForBusiness = $true
				$helloForBusinessDetails = $method.AdditionalProperties["displayName"]
				$mfaMethods.status = "enabled"
			}
			if ($method.AdditionalProperties["@odata.type"] -contains "#microsoft.graph.emailAuthenticationMethod")
			{
				# Email Authentication
				$mfaMethods.emailAuth = $true
				$mfaMethods.SSPREmail = $method.AdditionalProperties["emailAddress"]
				$mfaMethods.status = "enabled"
			}
			if ($method.AdditionalProperties["@odata.type"] -contains "#microsoft.graph.temporaryAccessPassAuthenticationMethod")
			{
				# Temporary Access pass
				$mfaMethods.tempPass = $true
				$tempPassDetails = $method.AdditionalProperties["lifetimeInMinutes"]
				$mfaMethods.status = "enabled"
			}
			if ($method.AdditionalProperties["@odata.type"] -contains "#microsoft.graph.passwordlessMicrosoftAuthenticatorAuthenticationMethod")
			{
				# Passwordless
				$mfaMethods.passwordLess = $true
				$passwordLessDetails = $method.AdditionalProperties["displayName"]
				$mfaMethods.status = "enabled"
			}
			if ($method.AdditionalProperties["@odata.type"] -contains "#microsoft.graph.softwareOathAuthenticationMethod")
			{
				# ThirdPartyAuthenticator
				$mfaMethods.softwareAuth = $true
				$mfaMethods.status = "enabled"
			}
			if ($mfaMethods.status -ne "enabled")
			{
				$mfaMethods.status = "disabled"
			}
		}
		Return $mfaMethods
	}
}
return Audit-CISAz212