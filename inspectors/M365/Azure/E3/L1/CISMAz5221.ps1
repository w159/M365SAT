# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISMAz5221
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMAz5221"
        ID               = "5.2.2.1"
        Title            = "(L1) Ensure multifactor authentication is enabled for all users in administrative roles"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "True for tenants >2019, False for tenants <2019"
        ExpectedValue    = "Number of Admin Accounts without MFA: 0"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Multifactor authentication (MFA) requires individuals to present at least two separate forms of authentication before access is granted. MFA adds a critical layer of security, making it significantly harder for attackers to gain unauthorized access to administrative accounts."
        Impact           = "Implementation of multifactor authentication for all users in administrative roles will necessitate a change to user routine. All users in administrative roles will be required to enroll in multifactor authentication using phone, SMS, or an authentication application. After enrollment, use of multifactor authentication will be required for future access to the environment."
        Remediation 	 = 'https://admindroid.sharepoint.com/:u:/s/external/EVzUDxQqxWdLj91v3mhAipsBt0GqNmUK5b4jFXPr181Svw?e=OOcfQn&isSPOFile=1'
        References       = @(
            @{ 'Name' = 'Require MFA for administrators'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-old-require-mfa-admin' }
        )
    }
    return $inspectorobject
}

function Audit-CISMAz5221
{
	try
	{
		$admins = ReportAdminNonMFA
		if ($admins.Count -ne 0)
		{
			$endobject = Build-CISMAz5221 -ReturnedValue ($admins.User) -Status "FAIL" -RiskScore "20" -RiskRating "Critical"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMAz5221 -ReturnedValue ($admins.User.Count) -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMAz5221 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}

function ReportAdminNonMFA
{
	$AdminRoleHolders = [System.Collections.Generic.List[Object]]::new()
	[array]$AdminRoles = Get-MgDirectoryRole | Where-Object { $_.DisplayName -like "*Administrator*" -or $_.DisplayName -eq "Global Reader"} | Select-Object DisplayName, Id | Sort-Object DisplayName
	ForEach ($Role in $AdminRoles)
	{
		[array]$RoleMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $Role.Id | Where-Object { $_.AdditionalProperties."@odata.type" -eq "#microsoft.graph.user" }
		ForEach ($Member in $RoleMembers)
		{
			$UserDetails = Get-MgUser -UserId $Member.Id
			$ReportLine = [PSCustomObject] @{
				User   = $UserDetails.UserPrincipalName
				Id	   = $UserDetails.Id
				Role   = $Role.DisplayName
				RoleId = $Role.Id
			}
			$AdminRoleHolders.Add($ReportLine)
		}
	}
	$AdminRoleHolders = $AdminRoleHolders | Sort-Object User
	$Unique = $AdminRoleHolders | Sort-Object User -Unique
	
	# Create a slightly different report where each user has their assigned roles in one record
	$UniqueAdminRoleHolders = [System.Collections.Generic.List[Object]]::new()
	ForEach ($User in $Unique)
	{
		$Records = $AdminRoleHolders | Where-Object { $_.id -eq $User.Id }
		$AdminRoles = $Records.Role -join ", "
		$ReportLine = [PSCustomObject] @{
			Id    = $User.Id
			User  = $User.User
			Roles = $AdminRoles
		}
		$UniqueAdminRoleHolders.Add($ReportLine)
	}
	
	# Retrieve member accounts that are licensed
	[array]$Users = Get-MgUser -Filter "assignedLicenses/`$count ne 0 and userType eq 'Member'" -ConsistencyLevel eventual -CountVariable Records -All
	
	$UserRegistrationDetails = [System.Collections.Generic.List[Object]]::new()
	ForEach ($User in $Users)
	{
		try
		{
			$Uri = "https://graph.microsoft.com/beta/reports/authenticationMethods/userRegistrationDetails/" + $User.Id
			$AccessMethodData = Invoke-MgGraphRequest -Uri $Uri -Method Get
			# Check if Admin
			$AdminAccount = $False; $AdminRolesHeld = $Null
			If ($user.id -in $UniqueAdminRoleHolders.Id)
			{
				$AdminAccount = $True
				$AdminRolesHeld = ($UniqueAdminRoleHolders | Where-Object { $_.Id -eq $User.Id } | Select-Object -ExpandProperty Roles)
			}
			$ReportLine = [PSCustomObject] @{
				User			 = $User.Displayname
				Id			     = $User.Id
				AdminAccount	 = $AdminAccount
				AdminRoles	     = $AdminRolesHeld
				MfaRegistered    = $AccessMethodData.isMfaRegistered
				defaultMfaMethod = $AccessMethodData.defaultMfaMethod
				isMfaCapable	 = $AccessMethodData.isMfaCapable
				Methods		     = $AccessMethodData.MethodsRegistered -join ", "
			}
			$UserRegistrationDetails.Add($ReportLine)
		}
		catch
		{
			#Write-Warning "User is no Account: $($User.Displayname)"
		}
		
	} #End ForEach
	
	[Array]$ProblemAdminAccounts = $UserRegistrationDetails | Where-Object { $_.AdminAccount -eq $True -and $_.MfaRegistered -eq $False }
	If ($ProblemAdminAccounts)
	{
		$ProblemAdminAccounts | Format-Table -AutoSize | Out-File "$path\CISMAz5221-GetAllAdminsNonMFAStatus.txt"
	}
	
	return $ProblemAdminAccounts
}

return Audit-CISMAz5221