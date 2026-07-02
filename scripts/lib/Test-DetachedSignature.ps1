function Test-DetachedSignature {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetPath,

        [Parameter(Mandatory = $true)]
        [SecureString]$PublicKeyPem,

        [string]$ExpectedKeyId,

        [string]$SignaturePath,

        [string]$DisplayName = 'File'
    )

    $credential = [System.Net.NetworkCredential]::new('', $PublicKeyPem)
    try {
        $publicKeyText = $credential.Password
        if ([string]::IsNullOrWhiteSpace($publicKeyText)) {
            throw 'PublicKeyPem is empty.'
        }
    }
    finally {
        $credential.Password = [string]::Empty
    }

    $resolvedTarget = (Resolve-Path -Path $TargetPath).Path

    if ([string]::IsNullOrWhiteSpace($SignaturePath)) {
        $SignaturePath = "$resolvedTarget.sig"
    }

    if (-not (Test-Path -Path $SignaturePath)) {
        throw "$DisplayName signature file not found: '$SignaturePath'. Sign the target file with Sign-Manifest.ps1 before deploying."
    }

    $sigContent = Get-Content -Path $SignaturePath -Raw -Encoding UTF8 | ConvertFrom-Json

    if ([string]$sigContent.algorithm -ne 'ECDSA-P256-SHA256') {
        throw "$DisplayName signature file '$SignaturePath' algorithm '$($sigContent.algorithm)' is not supported. Expected 'ECDSA-P256-SHA256'."
    }

    if (-not [string]::IsNullOrWhiteSpace($ExpectedKeyId) -and [string]$sigContent.keyId -ne $ExpectedKeyId) {
        throw "$DisplayName signature file '$SignaturePath' keyId '$([string]$sigContent.keyId)' does not match expected keyId '$ExpectedKeyId'."
    }

    if ([string]$sigContent.manifest -ne (Split-Path -Path $resolvedTarget -Leaf)) {
        throw "$DisplayName signature file '$SignaturePath' manifest field '$([string]$sigContent.manifest)' does not match target file '$resolvedTarget'."
    }

    $storedSignature = [string]$sigContent.signature
    if ([string]::IsNullOrWhiteSpace($storedSignature)) {
        throw "$DisplayName signature file '$SignaturePath' does not contain a signature value."
    }

    try {
        $signatureBytes = [Convert]::FromBase64String($storedSignature)
    }
    catch {
        throw "$DisplayName signature file '$SignaturePath' does not contain a valid Base64 ECDSA signature."
    }

    $targetContent = Get-Content -Path $resolvedTarget -Raw -Encoding UTF8
    $targetObject = $targetContent | ConvertFrom-Json
    $canonicalJson = $targetObject | ConvertTo-Json -Depth 10 -Compress
    $contentBytes = [System.Text.Encoding]::UTF8.GetBytes($canonicalJson)

    $ecdsa = [System.Security.Cryptography.ECDsa]::Create()
    if (-not ($ecdsa | Get-Member -Name 'ImportFromPem' -MemberType Method)) {
        throw 'Current PowerShell runtime does not support ECDSA ImportFromPem. Use PowerShell 7+ on .NET that supports ImportFromPem.'
    }

    $ecdsa.ImportFromPem($publicKeyText.ToCharArray())
    try {
        $isValid = $ecdsa.VerifyData(
            $contentBytes,
            $signatureBytes,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256
        )
    }
    finally {
        $ecdsa.Dispose()
    }

    if (-not $isValid) {
        throw "$DisplayName signature verification FAILED for '$resolvedTarget'. The file may have been tampered with."
    }

    Write-Host "$DisplayName signature verified OK: '$resolvedTarget'"
    return $true
}
