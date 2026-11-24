[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$KeepsafeRoot,

    [Parameter(Mandatory = $true)]
    [string]$ManifestPath,

    [string]$OutputRoot = (Join-Path $env:USERPROFILE 'Desktop\Keepsafe-Recovered')
)

# Local recovery utility for compatible Keepsafe iOS app-data extractions.
# Tested against one Keepsafe 11.11.1 extraction. Compatibility with other
# releases and backup layouts is not established. Original files are read-only.

$ErrorActionPreference = 'Stop'
$KeepsafeRoot = (Resolve-Path -LiteralPath $KeepsafeRoot).Path
$Documents = if ((Split-Path -Leaf $KeepsafeRoot) -ieq 'Documents') { $KeepsafeRoot } else { Join-Path $KeepsafeRoot 'Documents' }
$Primary = Join-Path $Documents 'primary'
$KeyPath = Join-Path $Documents 'skey.data'
$ManifestPath = (Resolve-Path -LiteralPath $ManifestPath).Path
$OutputRoot = [IO.Path]::GetFullPath($OutputRoot)
$LogPath = Join-Path $OutputRoot 'recovery-log.csv'

if (!(Test-Path -LiteralPath $KeyPath -PathType Leaf)) { throw "Key file not found: $KeyPath" }
if (!(Test-Path -LiteralPath $Primary -PathType Container)) { throw "Media folder not found: $Primary" }
if (!(Test-Path -LiteralPath $ManifestPath -PathType Leaf)) { throw "Manifest not found: $ManifestPath" }

$key = [IO.File]::ReadAllBytes($KeyPath)
if ($key.Length -ne 16) { throw "Expected a 16-byte skey.data file; found $($key.Length) bytes. Stopping." }
$manifest = Import-Csv -LiteralPath $ManifestPath
if (!$manifest -or $manifest.Count -eq 0) { throw 'Manifest has no records.' }

New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null
$results = New-Object System.Collections.Generic.List[object]
$verified = 0; $unverified = 0; $missing = 0; $failed = 0

function Test-MediaSignature([byte[]]$Bytes, [string]$Mime, [string]$Name) {
    $m = ([string]$Mime).ToLowerInvariant()
    if ($m -in @('image/jpeg','image/jpg') -or $Name -match '(?i)\.jpe?g$') {
        return ($Bytes.Length -ge 3 -and $Bytes[0] -eq 0xFF -and $Bytes[1] -eq 0xD8 -and $Bytes[2] -eq 0xFF)
    }
    if ($m -eq 'image/png' -or $Name -match '(?i)\.png$') {
        return ($Bytes.Length -ge 8 -and [BitConverter]::ToString($Bytes,0,8) -eq '89-50-4E-47-0D-0A-1A-0A')
    }
    if ($m -eq 'image/gif' -or $Name -match '(?i)\.gif$') {
        if ($Bytes.Length -lt 6) { return $false }
        $sig = [Text.Encoding]::ASCII.GetString($Bytes,0,6)
        return ($sig -eq 'GIF87a' -or $sig -eq 'GIF89a')
    }
    if ($m -eq 'image/webp' -or $Name -match '(?i)\.webp$') {
        return ($Bytes.Length -ge 12 -and [Text.Encoding]::ASCII.GetString($Bytes,0,4) -eq 'RIFF' -and [Text.Encoding]::ASCII.GetString($Bytes,8,4) -eq 'WEBP')
    }
    if ($m.StartsWith('video/') -or $m -in @('image/heic','image/heif','image/avif') -or $Name -match '(?i)\.(mp4|mov|heic|heif|avif|m4v)$') {
        return ($Bytes.Length -ge 12 -and [Text.Encoding]::ASCII.GetString($Bytes,4,4) -eq 'ftyp')
    }
    return $null
}

foreach ($item in $manifest) {
    $id = [string]$item.file_id
    $name = [string]$item.original_filename
    $mime = [string]$item.mime_type
    $size = 0L

    if ($id -notmatch '^[A-Za-z0-9]{5}$') {
        $failed++
        $results.Add([pscustomobject]@{file_id=$id; original_filename=$name; status='FAILED'; detail='File ID must be five alphanumeric characters'; output=''})
        continue
    }
    if (![long]::TryParse([string]$item.original_size, [ref]$size) -or $size -le 0 -or $size -gt [int]::MaxValue) {
        $failed++
        $results.Add([pscustomobject]@{file_id=$id; original_filename=$name; status='FAILED'; detail='Invalid or unsupported original size'; output=''})
        continue
    }

    $source = Join-Path (Join-Path $Primary $id.Substring(0,2)) ($id + ' 100')
    if (!(Test-Path -LiteralPath $source -PathType Leaf)) {
        $missing++
        $results.Add([pscustomobject]@{file_id=$id; original_filename=$name; status='MISSING'; detail='Encrypted source file not found'; output=$source})
        continue
    }

    $aes = $null; $decryptor = $null
    try {
        $data = [IO.File]::ReadAllBytes($source)
        if ($data.Length -lt 33) { throw 'Encrypted file is too short' }

        # Observed container for the tested backup: one byte containing the
        # padding count, followed by a 16-byte IV and AES-CBC ciphertext.
        $prefix = [int]$data[0]
        $cipherLength = $data.Length - 17
        $expectedPadding = 16 - ([int]($size % 16))
        if ($cipherLength -le 0 -or ($cipherLength % 16) -ne 0) { throw 'Ciphertext is not AES block-aligned' }
        if ($prefix -ne $expectedPadding -or $cipherLength -ne ($size + $expectedPadding)) {
            throw "Container and manifest size do not agree (prefix=$prefix, expected=$expectedPadding)"
        }

        $iv = New-Object byte[] 16
        [Array]::Copy($data,1,$iv,0,16)
        $cipher = New-Object byte[] $cipherLength
        [Array]::Copy($data,17,$cipher,0,$cipherLength)

        $aes = [Security.Cryptography.Aes]::Create()
        $aes.KeySize = 128
        $aes.BlockSize = 128
        $aes.Mode = [Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [Security.Cryptography.PaddingMode]::None
        $aes.Key = $key
        $aes.IV = $iv
        $decryptor = $aes.CreateDecryptor()
        $plain = $decryptor.TransformFinalBlock($cipher,0,$cipher.Length)
        if ($plain.Length -lt $size) { throw 'Decrypted payload is shorter than metadata size' }

        $recovered = New-Object byte[] ([int]$size)
        [Array]::Copy($plain,0,$recovered,0,[int]$size)
        $signature = Test-MediaSignature -Bytes $recovered -Mime $mime -Name $name
        if ($signature -eq $false) { throw 'Decrypted content does not match expected media signature' }

        $safeName = [IO.Path]::GetFileName($name)
        $safeName = [regex]::Replace($safeName, '[<>:"/\\|?*\x00-\x1F]', '_').TrimEnd('.', ' ')
        if ([string]::IsNullOrWhiteSpace($safeName)) { $safeName = 'recovered-media.bin' }
        # Prefixing the internal ID avoids collisions when different albums
        # contain files with the same original name.
        $outName = $id + '_' + $safeName
        $outPath = Join-Path $OutputRoot $outName
        [IO.File]::WriteAllBytes($outPath,$recovered)

        if ($null -eq $signature) {
            $unverified++
            $status = 'RECOVERED_UNVERIFIED'
            $detail = 'Decrypted and size-trimmed; no supported signature check for this format'
        } else {
            $verified++
            $status = 'RECOVERED_SIGNATURE_VERIFIED'
            $detail = 'Decrypted, size-checked and media signature matched'
        }
        $results.Add([pscustomobject]@{file_id=$id; original_filename=$name; status=$status; detail=$detail; output=$outPath})
    }
    catch {
        $failed++
        $results.Add([pscustomobject]@{file_id=$id; original_filename=$name; status='FAILED'; detail=$_.Exception.Message; output=''})
    }
    finally {
        if ($decryptor) { $decryptor.Dispose() }
        if ($aes) { $aes.Dispose() }
    }
}

$results | Export-Csv -LiteralPath $LogPath -NoTypeInformation -Encoding UTF8
Write-Host ''
Write-Host 'Keepsafe local recovery finished.' -ForegroundColor Green
Write-Host "Manifest records: $($manifest.Count)"
Write-Host "Recovered; supported signature verified: $verified"
Write-Host "Recovered; signature not checked: $unverified"
Write-Host "Missing encrypted media: $missing"
Write-Host "Failed / needs review: $failed"
Write-Host "Output folder: $OutputRoot"
Write-Host "Recovery log: $LogPath"
Write-Host 'The input backup files were not modified.'
