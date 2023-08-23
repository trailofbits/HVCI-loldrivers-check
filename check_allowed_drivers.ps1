<#
.SYNOPSIS

Compares the HVCI block list on the current system against the list of
vulnerable and malicious drivers from loldrivers.io

Company: Trail of Bits
Author: Michael Lin
Contributors: Yarden Shafir
License: Apache 2

.DESCRIPTION

check_allowed_drivers.ps1 reports the drivers from loldrivers.io which are allowed
by the current HVCI block list on the system.

Note: drivers which are allowed by the HVCI block list might still not load
      on a system due to other reasons such as architecture incompatibility,
      incorrect signature or EDR software.

.OUTPUTS

Outputs a list of drivers not blocked by the HVCI policy.
Potentially outputs a (short) list of drivers which may be allowed (see readme for details).
#>

$loldrivers = Invoke-WebRequest -Uri https://www.loldrivers.io/api/drivers.json | ConvertFrom-Json -AsHashTable
$cipolicypath = $env:TEMP + '\CIPolicyParser.ps1'
$recovered_policy_path = $env:TEMP + '\recovered_policy.xml'
Invoke-WebRequest -Uri https://gist.githubusercontent.com/mattifestation/92e545bf1ee5b68eeb71d254cec2f78e/raw/a9b55d31075f91b467a8a37b9d8b2d84a0aa856b/CIPolicyParser.ps1 -OutFile $cipolicypath

# CIPolicyParser is imcompatible with .NET Core so must be run in old powershell through Invoke-Command.
# save result of Invoke-Command into variable so it won't write output to console
$v = Invoke-Command -ScriptBlock { powershell {Import-Module ($env:TEMP + '\CIPolicyParser.ps1'); ConvertTo-CIPolicy -BinaryFilePath C:\Windows\System32\CodeIntegrity\driversipolicy.p7b -XmlFilePath ($env:TEMP + '\recovered_policy.xml')} }
[xml]$policy = Get-Content $recovered_policy_path

Remove-Item -Path $recovered_policy_path
Remove-Item -Path $cipolicypath

$file_rules = $policy.SiPolicy.FileRules
$signers = $policy.SiPolicy.Signers.Signer
$allowed = New-Object System.Collections.Generic.HashSet[string]
$maybe_allowed = New-Object System.Collections.Generic.HashSet[string]
$not_allowed = New-Object System.Collections.Generic.HashSet[string]

function hasBlockedHash($driver){
    foreach($hash in $file_rules.Deny.Hash){
        if(($hash) -and (
           ($hash -eq $driver.Authentihash.SHA256) -or
           ($hash -eq $driver.Authentihash.SHA1) -or 
           ($hash -eq $driver.Authentihash.MD5) -or 
           ($hash -eq $driver.SHA256) -or
           ($hash -eq $driver.SHA1) -or 
           ($hash -eq $driver.MD5)))
        {
            return $true
        }
    }
    return $false
}

function hasBlockedSigner($driver){
    $file_attrib = $file_rules.FileAttrib | Where-Object {$_.FileName -eq $driver.OriginalFilename}

    foreach($signer in $signers){
        $tbs = $signer.CertRoot.Value.ToLower()
        if(($driver.Signatures.Certificates.TBS.MD5 -contains $tbs) -or
           ($driver.Signatures.Certificates.TBS.SHA1 -contains $tbs) -or 
           ($driver.Signatures.Certificates.TBS.SHA256 -contains $tbs)){
            $blocked_files = $signer.FileAttribRef
            if(!$blocked_files -or ($blocked_files.RuleID -contains $file_attrib.ID)){
                return $true
            }
        }
        if ($tbs.Length -eq 96){
            # This entry has a SHA384 TBS so we can't know for sure if this driver matches
            if (($file_attrib) -and ($blocked_files.RuleID -contains $file_attrib.ID)){
                $maybe_allowed.Add(("MD5:{0} SHA1:{1} SHA256:{2}" -f $driver.MD5, $driver.SHA1, $driver.SHA256))
            }
        }
    }
    return $false
}

foreach ($driver in $loldrivers.KnownVulnerableSamples) {
    if(hasBlockedHash $driver){
        $not_allowed.Add(("MD5:{0} SHA1:{1} SHA256:{2}" -f $driver.MD5, $driver.SHA1, $driver.SHA256)) | Out-Null
        continue
    }

    $file_max_version = ($file_rules.Deny | Where-Object {$_.FileName -eq $driver.OriginalFilename}).MaximumFileVersion
    $version = (-split ($driver.FileVersion -replace ',\s*', '.'))[0]
    if($file_max_version -and $version -and ([version]$version -le $file_max_version)){
        $not_allowed.Add(("MD5:{0} SHA1:{1} SHA256:{2}" -f $driver.MD5, $driver.SHA1, $driver.SHA256)) | Out-Null
        continue
    }

    if(hasBlockedSigner $driver){
        $not_allowed.Add(("MD5:{0} SHA1:{1} SHA256:{2}" -f $driver.MD5, $driver.SHA1, $driver.SHA256)) | Out-Null
        continue
    }

    $allowed.Add(("MD5:{0} SHA1:{1} SHA256:{2}" -f $driver.MD5, $driver.SHA1, $driver.SHA256)) | Out-Null
}

Write-Output ("Number of blocked drivers: {0}" -f $not_allowed.Count)
Write-Output ("Number of allowed drivers: {0}`n" -f $allowed.Count)
Write-Output "Allowed drivers:"
$allowed | ForEach-Object {Write-Output "$_"}
if ($maybe_allowed.Count -ne 0){
    Write-Output "`nMaybe allowed:"
    $maybe_allowed | ForEach-Object {Write-Output "$_"}
}