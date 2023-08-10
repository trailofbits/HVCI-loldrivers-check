#Requires -Version 6.0
param (
        [Parameter(Position = 0, Mandatory)]
        [String]
        [ValidateScript({ [IO.File]::Exists((Resolve-Path $_).Path) })]
        $loldrivers_path,

        [Parameter(Position = 1, Mandatory)]
        [String]
        [ValidateScript({ [IO.File]::Exists((Resolve-Path $_).Path) })]
        $policy_path
)

$loldrivers = Get-Content $loldrivers_path | ConvertFrom-Json -AsHashtable
[xml]$policy = Get-Content $policy_path

$file_rules = $policy.SiPolicy.FileRules
$signers = $policy.SiPolicy.Signers.Signer
$allowed = New-Object System.Collections.Generic.HashSet[string]
$maybe_allowed = New-Object System.Collections.Generic.HashSet[string]

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
    }
    if($file_attrib){
        $maybe_allowed.Add(("MD5:{0} SHA1:{1} SHA256:{2}" -f $driver.MD5, $driver.SHA1, $driver.SHA256))
    }
    return $false
}

foreach ($driver in $loldrivers.KnownVulnerableSamples) {
    if(hasBlockedHash $driver){
        continue
    }

    $file_max_version = ($file_rules.Deny | Where-Object {$_.FileName -eq $driver.OriginalFilename}).MaximumFileVersion
    $version = (-split ($driver.FileVersion -replace ',\s*', '.'))[0]
    if($file_max_version -and $version -and ([version]$version -le $file_max_version)){
        continue
    }

    if(hasBlockedSigner $driver){
        continue
    }

    $allowed.Add(("MD5:{0} SHA1:{1} SHA256:{2}" -f $driver.MD5, $driver.SHA1, $driver.SHA256)) | Out-Null
}

Write-Output "Allowed:"
$allowed | ForEach-Object {Write-Output "$_"}
Write-Output "`nMaybe allowed:"
$maybe_allowed | ForEach-Object {Write-Output "$_"}