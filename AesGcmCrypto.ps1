[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Encrypt", "Decrypt")]
    [string]$Action,

    [Parameter(Mandatory=$false)]
    [string]$Key,

    [Parameter(Mandatory=$false)]
    [string]$Text,

    [Parameter(Mandatory=$false)]
    [string]$SourcePath,

    [Parameter(Mandatory=$false)]
    [string]$DestinationPath,

    [Parameter(Mandatory=$false)]
    [switch]$LineByLine
)

# C# source code for using CNG bcrypt.dll in .NET Framework (PowerShell 5.1)
$csharpCode = @"
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

public class AesGcmCng
{
    private const uint STATUS_SUCCESS = 0x00000000;
    private const string BCRYPT_AES_ALGORITHM = "AES";
    private const string BCRYPT_CHAINING_MODE_GCM = "ChainingModeGCM";
    private const string BCRYPT_CHAIN_MODE_PROPERTY = "ChainingMode";

    [StructLayout(LayoutKind.Sequential)]
    public struct BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO : IDisposable
    {
        public int cbSize;
        public int dwInfoVersion;
        public IntPtr pbNonce;
        public int cbNonce;
        public IntPtr pbAuthData;
        public int cbAuthData;
        public IntPtr pbTag;
        public int cbTag;
        public IntPtr pbMacContext;
        public int cbMacContext;
        public int cbAAD;
        public long cbData;
        public int dwFlags;

        public void Dispose()
        {
            if (pbNonce != IntPtr.Zero) { Marshal.FreeHGlobal(pbNonce); pbNonce = IntPtr.Zero; }
            if (pbTag != IntPtr.Zero) { Marshal.FreeHGlobal(pbTag); pbTag = IntPtr.Zero; }
            if (pbAuthData != IntPtr.Zero) { Marshal.FreeHGlobal(pbAuthData); pbAuthData = IntPtr.Zero; }
            if (pbMacContext != IntPtr.Zero) { Marshal.FreeHGlobal(pbMacContext); pbMacContext = IntPtr.Zero; }
        }
    }

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    private static extern uint BCryptOpenAlgorithmProvider(out IntPtr phAlgorithm, string pszAlgId, string pszImplementation, uint dwFlags);

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    private static extern uint BCryptSetProperty(IntPtr hObject, string pszProperty, byte[] pbInput, int cbInput, uint dwFlags);

    [DllImport("bcrypt.dll")]
    private static extern uint BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, uint dwFlags);

    [DllImport("bcrypt.dll")]
    private static extern uint BCryptGenerateSymmetricKey(IntPtr hAlgorithm, out IntPtr phKey, IntPtr pbKeyObject, int cbKeyObject, byte[] pbSecret, int cbSecret, uint dwFlags);

    [DllImport("bcrypt.dll")]
    private static extern uint BCryptDestroyKey(IntPtr hKey);

    [DllImport("bcrypt.dll")]
    private static extern uint BCryptEncrypt(
        IntPtr hKey,
        byte[] pbInput,
        int cbInput,
        ref BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO pPaddingInfo,
        byte[] pbIV,
        int cbIV,
        byte[] pbOutput,
        int cbOutput,
        out int pcbResult,
        uint dwFlags);

    [DllImport("bcrypt.dll")]
    private static extern uint BCryptDecrypt(
        IntPtr hKey,
        byte[] pbInput,
        int cbInput,
        ref BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO pPaddingInfo,
        byte[] pbIV,
        int cbIV,
        byte[] pbOutput,
        int cbOutput,
        out int pcbResult,
        uint dwFlags);

    public static byte[] Encrypt(byte[] key, byte[] nonce, byte[] plaintext, byte[] associatedData, out byte[] tag)
    {
        IntPtr hAlg = IntPtr.Zero;
        IntPtr hKey = IntPtr.Zero;
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo = new BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO();
        
        try
        {
            uint status = BCryptOpenAlgorithmProvider(out hAlg, BCRYPT_AES_ALGORITHM, null, 0);
            if (status != STATUS_SUCCESS)
                throw new CryptographicException("BCryptOpenAlgorithmProvider failed with status: 0x" + status.ToString("X"));

            byte[] chainMode = System.Text.Encoding.Unicode.GetBytes(BCRYPT_CHAINING_MODE_GCM);
            status = BCryptSetProperty(hAlg, BCRYPT_CHAIN_MODE_PROPERTY, chainMode, chainMode.Length, 0);
            if (status != STATUS_SUCCESS)
                throw new CryptographicException("BCryptSetProperty for ChainingModeGCM failed with status: 0x" + status.ToString("X"));

            status = BCryptGenerateSymmetricKey(hAlg, out hKey, IntPtr.Zero, 0, key, key.Length, 0);
            if (status != STATUS_SUCCESS)
                throw new CryptographicException("BCryptGenerateSymmetricKey failed with status: 0x" + status.ToString("X"));

            authInfo.cbSize = Marshal.SizeOf(typeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO));
            authInfo.dwInfoVersion = 1;
            
            authInfo.pbNonce = Marshal.AllocHGlobal(nonce.Length);
            Marshal.Copy(nonce, 0, authInfo.pbNonce, nonce.Length);
            authInfo.cbNonce = nonce.Length;

            tag = new byte[16]; // 128-bit authentication tag
            authInfo.pbTag = Marshal.AllocHGlobal(tag.Length);
            authInfo.cbTag = tag.Length;

            if (associatedData != null && associatedData.Length > 0)
            {
                authInfo.pbAuthData = Marshal.AllocHGlobal(associatedData.Length);
                Marshal.Copy(associatedData, 0, authInfo.pbAuthData, associatedData.Length);
                authInfo.cbAuthData = associatedData.Length;
            }

            int cbCiphertext = plaintext.Length;
            byte[] ciphertext = new byte[cbCiphertext];
            
            int cbResult = 0;
            status = BCryptEncrypt(hKey, plaintext, plaintext.Length, ref authInfo, null, 0, ciphertext, ciphertext.Length, out cbResult, 0);
            if (status != STATUS_SUCCESS)
                throw new CryptographicException("BCryptEncrypt failed with status: 0x" + status.ToString("X"));

            Marshal.Copy(authInfo.pbTag, tag, 0, tag.Length);

            return ciphertext;
        }
        finally
        {
            authInfo.Dispose();
            if (hKey != IntPtr.Zero) BCryptDestroyKey(hKey);
            if (hAlg != IntPtr.Zero) BCryptCloseAlgorithmProvider(hAlg, 0);
        }
    }

    public static byte[] Decrypt(byte[] key, byte[] nonce, byte[] ciphertext, byte[] associatedData, byte[] tag)
    {
        IntPtr hAlg = IntPtr.Zero;
        IntPtr hKey = IntPtr.Zero;
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo = new BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO();
        
        try
        {
            uint status = BCryptOpenAlgorithmProvider(out hAlg, BCRYPT_AES_ALGORITHM, null, 0);
            if (status != STATUS_SUCCESS)
                throw new CryptographicException("BCryptOpenAlgorithmProvider failed with status: 0x" + status.ToString("X"));

            byte[] chainMode = System.Text.Encoding.Unicode.GetBytes(BCRYPT_CHAINING_MODE_GCM);
            status = BCryptSetProperty(hAlg, BCRYPT_CHAIN_MODE_PROPERTY, chainMode, chainMode.Length, 0);
            if (status != STATUS_SUCCESS)
                throw new CryptographicException("BCryptSetProperty for ChainingModeGCM failed with status: 0x" + status.ToString("X"));

            status = BCryptGenerateSymmetricKey(hAlg, out hKey, IntPtr.Zero, 0, key, key.Length, 0);
            if (status != STATUS_SUCCESS)
                throw new CryptographicException("BCryptGenerateSymmetricKey failed with status: 0x" + status.ToString("X"));

            authInfo.cbSize = Marshal.SizeOf(typeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO));
            authInfo.dwInfoVersion = 1;
            
            authInfo.pbNonce = Marshal.AllocHGlobal(nonce.Length);
            Marshal.Copy(nonce, 0, authInfo.pbNonce, nonce.Length);
            authInfo.cbNonce = nonce.Length;

            authInfo.pbTag = Marshal.AllocHGlobal(tag.Length);
            Marshal.Copy(tag, 0, authInfo.pbTag, tag.Length);
            authInfo.cbTag = tag.Length;

            if (associatedData != null && associatedData.Length > 0)
            {
                authInfo.pbAuthData = Marshal.AllocHGlobal(associatedData.Length);
                Marshal.Copy(associatedData, 0, authInfo.pbAuthData, associatedData.Length);
                authInfo.cbAuthData = associatedData.Length;
            }

            int cbPlaintext = ciphertext.Length;
            byte[] plaintext = new byte[cbPlaintext];
            
            int cbResult = 0;
            status = BCryptDecrypt(hKey, ciphertext, ciphertext.Length, ref authInfo, null, 0, plaintext, plaintext.Length, out cbResult, 0);
            if (status != STATUS_SUCCESS)
                throw new CryptographicException("BCryptDecrypt failed with status: 0x" + status.ToString("X"));

            return plaintext;
        }
        finally
        {
            authInfo.Dispose();
            if (hKey != IntPtr.Zero) BCryptDestroyKey(hKey);
            if (hAlg != IntPtr.Zero) BCryptCloseAlgorithmProvider(hAlg, 0);
        }
    }
}
"@

# Load the C# class into PowerShell (only if not already loaded)
if (-not ([System.Management.Automation.PSTypeName]'AesGcmCng').Type) {
    Add-Type -TypeDefinition $csharpCode
}

# Helper: Convert Hex, Base64, or byte array key to byte array
function Convert-KeyToBytes {
    param(
        [Parameter(Mandatory=$true)]
        $Key
    )
    # If the key is already an array of bytes or object[] that can be cast to bytes
    if ($Key -is [System.Array]) {
        try {
            $bytes = [byte[]]$Key
            if ($bytes.Length -ne 32) {
                throw "Key length must be exactly 32 bytes (256 bits)."
            }
            return ,$bytes
        } catch {
            # Not convertible to byte array
        }
    }
    if ($Key -is [string]) {
        $cleanKey = $Key.Trim().Replace(" ", "").Replace("-", "").Replace(":", "")
        
        # Check if it's a 64-character Hex string (32 bytes)
        if ($cleanKey -match "^[0-9a-fA-F]{64}$") {
            try {
                $bytes = New-Object byte[] 32
                for ($i = 0; $i -lt 32; $i++) {
                    $bytes[$i] = [System.Convert]::ToByte($cleanKey.Substring($i * 2, 2), 16)
                }
                return ,$bytes
            } catch {
                # Fallback to base64 if hex parsing fails
            }
        }
        
        # Otherwise, try parsing as Base64
        try {
            $bytes = [System.Convert]::FromBase64String($cleanKey)
            if ($bytes.Length -ne 32) {
                throw "Key length must be exactly 32 bytes (256 bits). Decoded length is $($bytes.Length) bytes."
            }
            return ,$bytes
        } catch {
            throw "Failed to parse Key. It must be either a 64-character Hex string or a valid 32-byte Base64 string. Error: $_"
        }
    }
    throw "Invalid Key type. Must be byte array, Hex string, or Base64 string."
}


# ----------------- Public Functions -----------------

# Encrypt Text (returns combined Base64 string: Nonce + Tag + Ciphertext)
function Encrypt-AesGcm {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Plaintext,
        [Parameter(Mandatory=$true)]
        $Key
    )
    $keyBytes = Convert-KeyToBytes -Key $Key
    
    # Generate secure random 12-byte Nonce (standard for GCM)
    $nonceBytes = New-Object byte[] 12
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $rng.GetBytes($nonceBytes)

    # Convert Plaintext to bytes
    $plainBytes = [System.Text.Encoding]::UTF8.GetBytes($Plaintext)

    # Encrypt
    $tagBytes = $null
    $cipherBytes = [AesGcmCng]::Encrypt($keyBytes, $nonceBytes, $plainBytes, $null, [ref]$tagBytes)

    # Combine: Nonce (12 bytes) + Tag (16 bytes) + Ciphertext (remaining)
    $combinedBytes = New-Object byte[] (12 + 16 + $cipherBytes.Length)
    [System.Buffer]::BlockCopy($nonceBytes, 0, $combinedBytes, 0, 12)
    [System.Buffer]::BlockCopy($tagBytes, 0, $combinedBytes, 12, 16)
    [System.Buffer]::BlockCopy($cipherBytes, 0, $combinedBytes, 28, $cipherBytes.Length)

    return [System.Convert]::ToBase64String($combinedBytes)
}

# Decrypt Text (accepts combined Base64 string)
function Decrypt-AesGcm {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$EncryptedText,
        [Parameter(Mandatory=$true)]
        $Key
    )
    $keyBytes = Convert-KeyToBytes -Key $Key
    
    try {
        $combinedBytes = [System.Convert]::FromBase64String($EncryptedText)
    } catch {
        throw "Failed to parse EncryptedText as Base64 string."
    }

    if ($combinedBytes.Length -lt 28) {
        throw "Invalid encrypted data size. Must be at least 28 bytes (12-byte Nonce + 16-byte Tag)."
    }

    # Extract Nonce
    $nonceBytes = New-Object byte[] 12
    [System.Buffer]::BlockCopy($combinedBytes, 0, $nonceBytes, 0, 12)

    # Extract Tag
    $tagBytes = New-Object byte[] 16
    [System.Buffer]::BlockCopy($combinedBytes, 12, $tagBytes, 0, 16)

    # Extract Ciphertext
    $cipherLength = $combinedBytes.Length - 28
    $cipherBytes = New-Object byte[] $cipherLength
    [System.Buffer]::BlockCopy($combinedBytes, 28, $cipherBytes, 0, $cipherLength)

    # Decrypt
    $plainBytes = [AesGcmCng]::Decrypt($keyBytes, $nonceBytes, $cipherBytes, $null, $tagBytes)
    return [System.Text.Encoding]::UTF8.GetString($plainBytes)
}

# Encrypt File
function Encrypt-AesGcmFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$SourcePath,
        [Parameter(Mandatory=$true)]
        [string]$DestinationPath,
        [Parameter(Mandatory=$true)]
        $Key
    )
    $resolvedSource = Resolve-Path $SourcePath
    $plainBytes = [System.IO.File]::ReadAllBytes($resolvedSource.Path)
    $keyBytes = Convert-KeyToBytes -Key $Key
    
    # Generate secure random 12-byte Nonce
    $nonceBytes = New-Object byte[] 12
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $rng.GetBytes($nonceBytes)

    # Encrypt
    $tagBytes = $null
    $cipherBytes = [AesGcmCng]::Encrypt($keyBytes, $nonceBytes, $plainBytes, $null, [ref]$tagBytes)

    # Combine: Nonce (12 bytes) + Tag (16 bytes) + Ciphertext (remaining)
    $combinedBytes = New-Object byte[] (12 + 16 + $cipherBytes.Length)
    [System.Buffer]::BlockCopy($nonceBytes, 0, $combinedBytes, 0, 12)
    [System.Buffer]::BlockCopy($tagBytes, 0, $combinedBytes, 12, 16)
    [System.Buffer]::BlockCopy($cipherBytes, 0, $combinedBytes, 28, $cipherBytes.Length)

    [System.IO.File]::WriteAllBytes($DestinationPath, $combinedBytes)
    Write-Verbose "File encrypted successfully to: $DestinationPath"
}

# Decrypt File
function Decrypt-AesGcmFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$SourcePath,
        [Parameter(Mandatory=$true)]
        [string]$DestinationPath,
        [Parameter(Mandatory=$true)]
        $Key
    )
    $resolvedSource = Resolve-Path $SourcePath
    $combinedBytes = [System.IO.File]::ReadAllBytes($resolvedSource.Path)
    $keyBytes = Convert-KeyToBytes -Key $Key

    if ($combinedBytes.Length -lt 28) {
        throw "Invalid encrypted file size. Must be at least 28 bytes."
    }

    # Extract Nonce
    $nonceBytes = New-Object byte[] 12
    [System.Buffer]::BlockCopy($combinedBytes, 0, $nonceBytes, 0, 12)

    # Extract Tag
    $tagBytes = New-Object byte[] 16
    [System.Buffer]::BlockCopy($combinedBytes, 12, $tagBytes, 0, 16)

    # Extract Ciphertext
    $cipherLength = $combinedBytes.Length - 28
    $cipherBytes = New-Object byte[] $cipherLength
    [System.Buffer]::BlockCopy($combinedBytes, 28, $cipherBytes, 0, $cipherLength)

    # Decrypt
    $plainBytes = [AesGcmCng]::Decrypt($keyBytes, $nonceBytes, $cipherBytes, $null, $tagBytes)
    
    [System.IO.File]::WriteAllBytes($DestinationPath, $plainBytes)
    Write-Verbose "File decrypted successfully to: $DestinationPath"
}

# Encrypt File Line by Line
function Encrypt-AesGcmLineByLine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$SourcePath,
        [Parameter(Mandatory=$true)]
        [string]$DestinationPath,
        [Parameter(Mandatory=$true)]
        $Key
    )
    $resolvedSource = Resolve-Path $SourcePath
    $lines = [System.IO.File]::ReadLines($resolvedSource.Path)
    $keyBytes = Convert-KeyToBytes -Key $Key

    $writer = New-Object System.IO.StreamWriter($DestinationPath, $false, [System.Text.Encoding]::UTF8)
    try {
        foreach ($line in $lines) {
            if ($null -ne $line) {
                $encryptedLine = Encrypt-AesGcm -Plaintext $line -Key $keyBytes
                $writer.WriteLine($encryptedLine)
            }
        }
    } finally {
        $writer.Dispose()
    }
    Write-Verbose "File encrypted line-by-line successfully to: $DestinationPath"
}
# Decrypt File Line by Line
function Decrypt-AesGcmLineByLine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$SourcePath,
        [Parameter(Mandatory=$true)]
        [string]$DestinationPath,
        [Parameter(Mandatory=$true)]
        $Key
    )
    $resolvedSource = Resolve-Path $SourcePath
    $lines = [System.IO.File]::ReadLines($resolvedSource.Path)
    $keyBytes = Convert-KeyToBytes -Key $Key

    $writer = New-Object System.IO.StreamWriter($DestinationPath, $false, [System.Text.Encoding]::UTF8)
    try {
        foreach ($line in $lines) {
            if (-not [string]::IsNullOrWhiteSpace($line)) {
                $decryptedLine = Decrypt-AesGcm -EncryptedText $line -Key $keyBytes
                $writer.WriteLine($decryptedLine)
            } else {
                $writer.WriteLine("")
            }
        }
    } finally {
        $writer.Dispose()
    }
    Write-Verbose "File decrypted line-by-line successfully to: $DestinationPath"
}

# ----------------- CLI Argument Handler -----------------
if ($Action) {
    if (-not $Key) {
        Write-Error "The -Key parameter is required."
        exit 1
    }

    try {
        if ($Action -eq "Encrypt") {
            if ($Text) {
                # Encrypting text
                $result = Encrypt-AesGcm -Plaintext $Text -Key $Key
                Write-Output $result
            } elseif ($SourcePath -and $DestinationPath) {
                if ($LineByLine) {
                    # Encrypting file line-by-line
                    Encrypt-AesGcmLineByLine -SourcePath $SourcePath -DestinationPath $DestinationPath -Key $Key
                    Write-Output "Success: File encrypted line-by-line to $DestinationPath"
                } else {
                    # Encrypting file as a single block
                    Encrypt-AesGcmFile -SourcePath $SourcePath -DestinationPath $DestinationPath -Key $Key
                    Write-Output "Success: File encrypted to $DestinationPath"
                }
            } else {
                Write-Error "You must specify either -Text or both -SourcePath and -DestinationPath."
                exit 1
            }
        } elseif ($Action -eq "Decrypt") {
            if ($Text) {
                # Decrypting text
                $result = Decrypt-AesGcm -EncryptedText $Text -Key $Key
                Write-Output $result
            } elseif ($SourcePath -and $DestinationPath) {
                if ($LineByLine) {
                    # Decrypting file line-by-line
                    Decrypt-AesGcmLineByLine -SourcePath $SourcePath -DestinationPath $DestinationPath -Key $Key
                    Write-Output "Success: File decrypted line-by-line to $DestinationPath"
                } else {
                    # Decrypting file as a single block
                    Decrypt-AesGcmFile -SourcePath $SourcePath -DestinationPath $DestinationPath -Key $Key
                    Write-Output "Success: File decrypted to $DestinationPath"
                }
            } else {
                Write-Error "You must specify either -Text or both -SourcePath and -DestinationPath."
                exit 1
            }
        }
    } catch {
        Write-Error "Cryptography operation failed: $_"
        exit 1
    }
}
