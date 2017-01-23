class OctopusCrypt {
    [byte[]] static hidden GetMasterKey([string]$Password) {
        return (New-Object System.Security.Cryptography.Rfc2898DeriveBytes @($Password, [System.Text.Encoding]::UTF8.GetBytes("Octopuss"), 1000) | % GetBytes 16)
    }
    [string] Encrypt([string]$Password, [string]$Value) {
        $csp = New-Object System.Security.Cryptography.AesCryptoServiceProvider
        $csp.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $csp.KeySize = 128
        $csp.BlockSize = 128
        $csp.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $csp.Key = [OctopusCrypt]::GetMasterKey($Password)
        $iv = $csp.IV
        $encryptor = $csp.CreateEncryptor()

        [byte[]]$plainText = [System.Text.Encoding]::UTF8.GetBytes($Value)
        $ms = New-Object System.IO.MemoryStream
        $cryptoStream = New-Object System.Security.Cryptography.CryptoStream  @($ms, $encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)
        $cryptoStream.Write($plainText, 0, $plainText.Length)
        $cryptoStream.FlushFinalBlock()
        
        return ([System.Convert]::ToBase64String($ms.ToArray()) + '|' + [System.Convert]::ToBase64String($iv))
    }
    [string] Decrypt([string]$Password, [string]$Value) {
        $csp = New-Object System.Security.Cryptography.AesCryptoServiceProvider
        $csp.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $csp.KeySize = 128
        $csp.BlockSize = 128
        $csp.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $csp.Key = [OctopusCrypt]::GetMasterKey($Password)
        $iv = [System.Convert]::FromBase64String($Value.Split('|')[1])
        $csp.IV = $iv
        $decryptor = $csp.CreateDecryptor()

        $encodedBytes = [System.Convert]::FromBase64String($Value.Split('|')[0])
        $decodedBytes = $decryptor.TransformFinalBlock($encodedBytes, 0, $encodedBytes.Count)

        return ([System.Text.Encoding]::UTF8.GetString(($decodedBytes)))
    }
    [string] Hash([string]$Value) {
        [byte[]]$plainText = [System.Text.Encoding]::UTF8.GetBytes($Value)
        $salt = New-Object byte[] 16
        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($salt)
        $hashedValue = New-Object System.Security.Cryptography.Rfc2898DeriveBytes @($plainText, $salt, 1000) | % GetBytes 24

        return ((1000).ToString('X') + '$' + [System.Convert]::ToBase64String($salt) + '$' + [System.Convert]::ToBase64String($hashedValue))
    }
}