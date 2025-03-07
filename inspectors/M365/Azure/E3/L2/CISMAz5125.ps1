#Requires -module Az.Accounts
# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMAz5125
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMAz5125"
        ID               = "5.1.2.5"
        Title            = "(L2) Ensure the option to remain signed in is hidden"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "hideKeepMeSignedIn: False"
        ExpectedValue    = "hideKeepMeSignedIn: True"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Allowing users to choose to stay signed in can pose security risks, particularly if the user logs into their account on a shared or public computer. An unauthorized individual could easily access associated cloud data if the option to remain signed in is available."
        Impact           = "Once this setting is hidden users will no longer be prompted upon sign-in with the message Stay signed in?. This may mean users will be forced to sign in more frequently. Important: some features of SharePoint Online and Office 2010 have a dependency on users remaining signed in. If you hide this option, users may get additional and unexpected sign in prompts."
        Remediation	 	 = 'https://entra.microsoft.com/#view/Microsoft_AAD_UsersAndTenants/UserManagementMenuBlade/~/UserSettings/menuId/UserSettings'
        References       = @(
            @{ 'Name' = 'Reauthentication prompts and session lifetime for Microsoft Entra multifactor authentication'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/authentication/concepts-azure-multi-factor-authentication-prompts-session-lifetime' },
            @{ 'Name' = 'Manage the "Stay signed in?" prompt'; 'URL' = 'https://learn.microsoft.com/en-us/entra/fundamentals/how-to-manage-stay-signed-in-prompt' },
            @{ 'Name' = 'Office 365 disable stay signed in prompt'; 'URL' = 'https://www.alitajran.com/office-365-disable-stay-signed-in-prompt/' }
        )
    }
    return $inspectorobject
}

function Audit-CISMAz5125
{
	try
	{
		$AffectedOptions = @()
		# Actual Script
		$KeepMeSignedIn = Invoke-MultiMicrosoftAPI -Url 'https://main.iam.ad.ext.azure.com/api/LoginTenantBrandings/0' -Resource "74658136-14ec-4630-ad9b-26e160ff0fc6" -Method 'GET'
		
		# Validation
		if ($KeepMeSignedIn.hideKeepMeSignedIn -ne $True)
		{
			$AffectedOptions += "hideKeepMeSignedIn: $($KeepMeSignedIn.hideKeepMeSignedIn)"
		}
		if ($AffectedOptions.count -igt 0)
		{
			$KeepMeSignedIn | Format-List | Out-File "$path\CISMAz5125-LoginSettingsTenant.txt"
			$endobject = Build-CISMAz5125 -ReturnedValue ($AffectedOptions) -Status "FAIL" -RiskScore "10" -RiskRating "High"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMAz5125 -ReturnedValue "hideKeepMeSignedIn: $($KeepMeSignedIn.hideKeepMeSignedIn)" -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMAz5125 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}

function Invoke-MultiMicrosoftAPI
{
	param (
		#The whole URL to call
		[Parameter()]
		[String]$Url,
		#The Name of the Resource
		[Parameter()]
		[String]$Resource,
		[Parameter()]
		#Body if a POST or PUT
		[Object]$Body,
		[Parameter()]
		#Specify the HTTP Method you wish to use. Defaults to GET
		[ValidateSet("GET", "POST", "OPTIONS", "DELETE", "PUT")]
		[String]$Method = "GET"
	)
	
	try
	{
		[Microsoft.Azure.Commands.Profile.Models.Core.PSAzureContext]$Context = (Get-AzContext | Select-Object -first 1)
	}
	catch
	{
		Connect-AzAccount -ErrorAction Stop
		[Microsoft.Azure.Commands.Profile.Models.Core.PSAzureContext]$Context = (Get-AzContext | Select-Object -first 1)
	}
	
	#Specify Resource
	$apiToken = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($context.Account, $context.Environment, $context.Tenant.Id, $null, "Never", $null, $Resource)
	
	# Creating the important header
	$header = [ordered]@{
		'Authorization' = 'Bearer ' + $apiToken.AccessToken.ToString()
		'Content-Type'  = 'application/json'
		'X-Requested-With' = 'XMLHttpRequest'
		'x-ms-client-request-id' = [guid]::NewGuid()
		'x-ms-correlation-id' = [guid]::NewGuid()
	}
	# URL Where PUT Request is being done. You can extract this from F12 
	
	$method = 'GET'
	
	#In Case your Method is PUT or POST to edit something. Change things here
	
	if ($method -eq 'PUT')
	{
		# Remediation Scripts HERE
		$contentpart1 = '{"restrictNonAdminUsers":false}'
		
		#Convert the content (DUMMY)
		$Body = $contentpart1
		
		#Execute Request
		$Response = Invoke-RestMethod -Uri $Url -Headers $header -Method $Method -Body $Body -ErrorAction Stop
	}
	elseif ($method -eq 'POST')
	{
		#Execute Request
		$Response = Invoke-RestMethod -Uri $Url -Headers $header -Method $Method -Body $Body -ErrorAction Stop
	}
	elseif ($method -eq 'GET')
	{
		#Execute Request
		$Response = Invoke-RestMethod -Uri $Url -Headers $header -Method $Method -ErrorAction Stop
	}
	return $Response
}
return Audit-CISMAz5125