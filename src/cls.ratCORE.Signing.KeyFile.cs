/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * 
 * Program:                         ratCORE.Signing.KeyFile
 * Description:                     Represents the file structure of a key file.
 *                                  IMPORTANT:
 *                                  The key file contains the necessary signature information to sign files.
 *                                  This key file must be kept secret!
 * Current Version:                 1.0.9421.1309 (17.10.2025)
 * Company:                         ratware
 * Author:                          Tom V. (ratware)
 * Email:                           info@ratware.de
 * Copyright:                       © 2025 ratware
 * License:                         Creative Commons Attribution 4.0 International (CC BY 4.0)
 * License URL:                     https://creativecommons.org/licenses/by/4.0/
 * Filename:                        cls.ratCORE.Signing.KeyFile.cs
 * Language:                        C# (.NET 8)
 * 
 * You are free to use, share, and adapt this code for any purpose,
 * even commercially, provided that proper credit is given to the author.
 * See the license link above for details.
 *  
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * 
 * History:
 * 
 *     - 17.10.2025 - Tom V. (ratware) - Version 1.0.9421.1309
 *       Reviewed and approved
 * 
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * 
 * Current file structure (Version 1):
 * 
 * VERSION      : 1
 * ALG          : Signature Algorithm:                             ECDSA-P256
 * AEAD         : Authenticated encryption with associated data:   AES-256-GCM
 * KDF          : Key derivation function
 * - NAME       : Password-based key derivation function:          PBKDF2-SHA256
 * - SALT       : Salt
 * - ITERATIONS : Iterations
 * - KEYLEN     : Key length
 * ENCSEED      : Encryption seed
 * - NONCE      : Pseudo-random number used once
 * - CT         : Ciphertext
 * - TAG        : AES-GCM Tags
 * PUB          : Public key
 * KEYID        : Key id
 * CREATEDUTC   : Utc creation date ISO 8601
 * 
 */

using System.Text.Json.Serialization;

namespace ratCORE.Signing
{
    public sealed class KeyFile
    {
        public const int CurrentVersion = 1;
        public const string AlgP256 = "ecdsa-p256";
        public const string AeadAes256Gcm = "aes-256-gcm";
        public const string KdfPbkdf2Sha256 = "pbkdf2-sha256";

        [JsonPropertyName("version")] public int Version { get; init; } = CurrentVersion;
        [JsonPropertyName("alg")] public string Algorithm { get; init; } = AlgP256;
        [JsonPropertyName("aead")] public string Aead { get; init; } = AeadAes256Gcm;

        [JsonPropertyName("kdf")] public KeyFileKdf Kdf { get; init; } = new();
        [JsonPropertyName("encSeed")] public KeyFileEncSeed EncSeed { get; init; } = new();

        [JsonPropertyName("pub")] public string PublicKeyBase64 { get; init; } = "";
        [JsonPropertyName("keyId")] public string KeyId { get; init; } = "";
        
        [JsonPropertyName("createdUtc")] public string CreatedUtc { get; init; } = "";
    }

    public sealed class KeyFileKdf
    {
        [JsonPropertyName("name")] public string Name { get; init; } = KeyFile.KdfPbkdf2Sha256;
        [JsonPropertyName("salt")] public string SaltBase64 { get; init; } = "";
        [JsonPropertyName("iterations")] public int Iterations { get; init; }
        [JsonPropertyName("keyLen")] public int KeyLen { get; init; }
    }

    public sealed class KeyFileEncSeed
    {
        [JsonPropertyName("nonce")] public string NonceBase64 { get; init; } = "";
        [JsonPropertyName("ct")] public string CiphertextBase64 { get; init; } = "";
        [JsonPropertyName("tag")] public string TagBase64 { get; init; } = "";
    }
}
