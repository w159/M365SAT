# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMEx2111
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMEx2111"
        ID               = "2.1.11"
        Title            = "(L2) Ensure comprehensive attachment filtering is applied"
        ProductFamily    = "Microsoft Exchange"
        DefaultValue     = "28 unique file types"
        ExpectedValue    = "120 unique file types"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Blocking known malicious file types can help prevent malware-infested files from infecting systems or performing other malicious activities, such as phishing and data extraction. A comprehensive attachment filtering policy, which includes blocking obsolete file formats, legacy binary files, and compressed files, is essential for mitigating risks such as Business Email Compromise (BEC). By allowing only the file types relevant to business operations, organizations can reduce the attack surface."
        Impact           = "For file types that are business necessary users will need to use other organizationally approved methods to transfer blocked extension types between business partners"
        Remediation 	 = 'New-MalwareFilterPolicy @Policy -FileTypes $L2Extensions; New-MalwareFilterRule @Rule'
        References       = @(
            @{ 'Name' = 'Configure anti-malware policies in EOP'; 'URL' = 'https://learn.microsoft.com/en-us/defender-office-365/anti-malware-policies-configure?view=o365-worldwide' }
        )
    }
    return $inspectorobject
}

function Inspect-CISMEx2111
{
	Try
	{
		# This is the list with filetypes that should be filtered based on the CIS benchmark
		$L2Extensions = @(
		"7z", "a3x", "ace", "ade", "adp", "ani", "app", "appinstaller",
		"applescript", "application", "appref-ms", "appx", "appxbundle", "arj",
		"asd", "asx", "bas", "bat", "bgi", "bz2", "cab", "chm", "cmd", "com",
		"cpl", "crt", "cs", "csh", "daa", "dbf", "dcr", "deb",
		"desktopthemepackfile", "dex", "diagcab", "dif", "dir", "dll", "dmg",
		"doc", "docm", "dot", "dotm", "elf", "eml", "exe", "fxp", "gadget", "gz",
		"hlp", "hta", "htc", "htm", "htm", "html", "html", "hwpx", "ics", "img",
		"inf", "ins", "iqy", "iso", "isp", "jar", "jnlp", "js", "jse", "kext",
		"ksh", "lha", "lib", "library-ms", "lnk", "lzh", "macho", "mam", "mda",
		"mdb", "mde", "mdt", "mdw", "mdz", "mht", "mhtml", "mof", "msc", "msi",
		"msix", "msp", "msrcincident", "mst", "ocx", "odt", "ops", "oxps", "pcd",
		"pif", "plg", "pot", "potm", "ppa", "ppam", "ppkg", "pps", "ppsm", "ppt",
		"pptm", "prf", "prg", "ps1", "ps11", "ps11xml", "ps1xml", "ps2", 
		"ps2xml", "psc1", "psc2", "pub", "py", "pyc", "pyo", "pyw", "pyz", 
		"pyzw", "rar", "reg", "rev", "rtf", "scf", "scpt", "scr", "sct",
		"searchConnector-ms", "service", "settingcontent-ms", "sh", "shb", "shs",
		"shtm", "shtml", "sldm", "slk", "so", "spl", "stm", "svg", "swf", "sys",
		"tar", "theme", "themepack", "timer", "uif", "url", "uue", "vb", "vbe",
		"vbs", "vhd", "vhdx", "vxd", "wbk", "website", "wim", "wiz", "ws", "wsc",
		"wsf", "wsh", "xla", "xlam", "xlc", "xll", "xlm", "xls", "xlsb", "xlsm",
		"xlt", "xltm", "xlw", "xml", "xnk", "xps", "xsl", "xz", "z"
		)

		# Initialize counters
		$Violation = @()
		$ExtensionReport = @()
		$MissingCount = 0

		#MalwarePolicy
		$MalwarePolicies = Get-MalwareFilterPolicy
		foreach ($MalwarePolicy in $MalwarePolicies){
			if ($MalwarePolicy.EnableFileFilter -eq $false) {
				Write-Warning "$($MalwarePolicy.Identity): Common Attachments Filter is disabled"
				$Violation += "$($MalwarePolicy.Identity): Common Attachments Filter is disabled"
			}
		}
		#FilterRules
		$FilterRules = Get-MalwareFilterRule
		foreach ($FilterRule in $FilterRules){
			if ($FoundRule.State -eq 'Disabled' -or $null) {
				Write-Warning "WARNING: The Anti-malware rule is disabled."
				$Violation += "Anti-Malware Rule is disabled"
			}
		}
		#ExtensionPolicy
		$ExtensionPolicies = Get-MalwareFilterPolicy | Where-Object {$_.FileTypes.Count -ilt 120}
		foreach($ExtensionPolicy in $ExtensionPolicies){
			if ($ExtensionPolicies.FileTypes.Count -eq 0){
				Write-Warning "$($ExtensionPolicy.Identity) does not have any filetypes filtered!"
				$Violation += "Amount of Extensions in $($ExtensionPolicy.Identity): $(($MalwarePolicy.FileTypes).Count)"
				$MissingExtensions = $L2Extensions | Where-Object { $extension = $_; -not $ExtensionPolicy.FileTypes.Contains($extension) }
				if ($MissingExtensions.Count -igt 0){
					$MissingCount++
					 $ExtensionReport += @{
					 Identity = $policy.Identity 
					MissingExtensions = $MissingExtensions -join ', '
					}
				}
			}else{
				Write-Warning "$($ExtensionPolicy.Identity) does contain only $(($ExtensionPolicies.FileTypes).Count) extensions!"
				$Violation += "Amount of Extensions in $($ExtensionPolicy.Identity): $(($MalwarePolicy.FileTypes).Count)"
				$MissingExtensions = $L2Extensions | Where-Object { $extension = $_; -not $ExtensionPolicy.FileTypes.Contains($extension) }
				if ($MissingExtensions.Count -igt 0){
					$MissingCount++
					 $ExtensionReport += @{
					 Identity = $ExtensionPolicy.Identity 
					 MissingExtensions = $MissingExtensions -join ', '
					}
				}
			}
		}

		#Wrapup report
		if ($MissingCount -igt 0) {
			foreach ($fpolicy in $ExtensionReport) {
				$MissingExtensions = $fpolicy.MissingExtensions.Split(",")
				$Violation += "$($fpolicy.Identity) is missing the following extension filters: $($fpolicy.MissingExtensions) \n"
			}
		}

		#Final check
		if ($Violation.Count -igt 0)
		{
			$Violation | Format-Table -AutoSize | Out-File "$path\CISMEx2111-MalwareFilterRule.txt"
			$endobject = Build-CISMEx2111 -ReturnedValue $Violation -Status "FAIL" -RiskScore "10" -RiskRating "Medium"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMEx2111 -ReturnedValue "120 unique file types" -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
		
		}
	catch
	{
		$endobject = Build-CISMEx2111 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
	
}

return Inspect-CISMEx2111


