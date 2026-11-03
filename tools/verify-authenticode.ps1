param(
    [Parameter(Mandatory=$true)][string]$InstallerPath,
    [Parameter(Mandatory=$true)][string]$ApplicationPath,
    [Parameter(Mandatory=$true)][string]$PublisherSubject
)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$rows = @()
foreach ($targetPath in @($InstallerPath, $ApplicationPath)) {
    $signature = Get-AuthenticodeSignature -LiteralPath $targetPath
    $subject = if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { $null }
    $thumbprint = if ($signature.SignerCertificate) { $signature.SignerCertificate.Thumbprint } else { $null }
    $codeSigning = $false
    if ($signature.SignerCertificate) {
        $codeSigning = @($signature.SignerCertificate.EnhancedKeyUsageList | Where-Object {
            $_.ObjectId -eq '1.3.6.1.5.5.7.3.3' -or $_.ObjectId.Value -eq '1.3.6.1.5.5.7.3.3'
        }).Count -gt 0
    }
    $rows += [pscustomobject]@{
        status = $signature.Status.ToString()
        subject = $subject
        thumbprint = $thumbprint
        publisherMatches = $subject -ceq $PublisherSubject
        timestampPresent = $null -ne $signature.TimeStamperCertificate
        codeSigning = $codeSigning
    }
}
$sameSigner = $rows.Count -eq 2 -and $rows[0].thumbprint -and ($rows[0].thumbprint -ceq $rows[1].thumbprint)
$valid = $sameSigner -and @($rows | Where-Object { $_.status -ne 'Valid' -or !$_.publisherMatches -or !$_.timestampPresent -or !$_.codeSigning }).Count -eq 0
[pscustomobject]@{valid=[bool]$valid; sameSigner=[bool]$sameSigner; signatures=$rows} | ConvertTo-Json -Depth 5 -Compress
if (!$valid) { exit 1 }
