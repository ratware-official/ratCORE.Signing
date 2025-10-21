/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * 
 * Program:                         ratCORE.Signing.SignatureFile
 * Description:                     Represents the file structure of a signature file.
 *                                  IMPORTANT:
 *                                  The signature file is required to verify a published file.
 *                                  This signature file is also public.
 * Current Version:                 1.0.9421.1309 (17.10.2025)
 * Company:                         ratware
 * Author:                          Tom V. (ratware)
 * Email:                           info@ratware.de
 * Copyright:                       © 2025 ratware
 * License:                         Creative Commons Attribution 4.0 International (CC BY 4.0)
 * License URL:                     https://creativecommons.org/licenses/by/4.0/
 * Filename:                        cls.ratCORE.Signing.SignatureFile.cs
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
 * MAGIC        : 'RSIG' (ratCORE Signing)
 * VERSION      : 1
 * ALG          : Signature Algorithm:   ECDSA-P256
 * HASH         : Hash Algorithm:        SHA256
 * PUB          : Public key
 * SIG          : Signature
 * COMMENT      : File comment
 * CREATEDUTC   : Utc creation date ISO 8601
 * FILENAME     : File name of the signed file.
 * 
 */

using System.Text.Json.Serialization;

namespace ratCORE.Signing
{
    public sealed class SignatureFile
    {
        public const string MagicConst = "RSIG";
        public const int CurrentVersion = 1;
        public const string AlgP256 = "ecdsa-p256";
        public const string AlgSha256 = "sha256";

        [JsonPropertyName("magic")] public string Magic { get; init; } = MagicConst;
        [JsonPropertyName("version")] public int Version { get; init; } = CurrentVersion;

        [JsonPropertyName("alg")] public string Algorithm { get; init; } = AlgP256;
        [JsonPropertyName("hash")] public string HashAlgorithm { get; init; } = AlgSha256;

        [JsonPropertyName("pub")] public string PublicKeyBase64 { get; init; } = "";
        [JsonPropertyName("sig")] public string SignatureBase64 { get; init; } = "";

        [JsonPropertyName("comment")] public string? TrustedComment { get; init; }

        [JsonPropertyName("createdUtc")] public string CreatedUtc { get; init; } = "";
        [JsonPropertyName("fileName")] public string? FileNameHint { get; init; }
    }
}
