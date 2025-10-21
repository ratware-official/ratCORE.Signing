/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * 
 * Program:                         ratCORE.Signing.KeyGen
 * Description:                     Creates the key pair based by a secret password and creates the key file.
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
 * Filename:                        cls.ratCORE.Signing.KeyGen.cs
 * Language:                        C# (.NET 8)
 * Required:                        cls.ratCORE.Signing.KeyFile.cs
 * KeyGen only:                     cls.ratCORE.Signing.KeyGen.cs, cls.ratCORE.Signing.KeyFile.cs
 * Not required for KeyGen only:    cls.ratCORE.Signing.Verifier.cs, cls.ratCORE.Signing.Signer.cs, cls.ratCORE.Signing.SignatureFile.cs
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
 */

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ratCORE.Signing
{
    public sealed class KeyGen
    {
        /// <summary>Generates the key pair and creates the key file.</summary>
        /// <param name="outputDirectory">Output directory for the key file.</param>
        /// <param name="password">The secret password.</param>
        /// <param name="iterations">The number of iterations.</param>
        /// <param name="keyName">The key name. Its part of the key file name.</param>
        public static async Task<string> GenerateAsync(
            string outputDirectory,
            string password,
            int iterations = 300_000,
            string? keyName = null,
            CancellationToken ct = default)
        {
            Directory.CreateDirectory(outputDirectory);

            // create ECDSA-P256 keypair
            using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var p = ecdsa.ExportParameters(true);
            if (p.D is null || p.Q.X is null || p.Q.Y is null)
                throw new InvalidOperationException("ECDSA parameters missing.");

            // public key as uncompressed point: 0x04 || X || Y (65 bytes)
            var pub = new byte[65];
            pub[0] = 0x04;
            Buffer.BlockCopy(p.Q.X, 0, pub, 1, 32);
            Buffer.BlockCopy(p.Q.Y, 0, pub, 33, 32);

            // derive KEK using PBKDF2-SHA256
            var salt = RandomNumberGenerator.GetBytes(16);
            const int keyLen = 32; // AES-256
            var kek = Rfc2898DeriveBytes.Pbkdf2(
                Encoding.UTF8.GetBytes(password),
                salt,
                iterations,
                HashAlgorithmName.SHA256,
                keyLen);

            // encrypt private scalar D (32 bytes) with AES-GCM
            var nonce = RandomNumberGenerator.GetBytes(12);
            var ctD = new byte[32];
            var tag = new byte[16];
            using (var aes = new AesGcm(kek, tagSizeInBytes: 16))
                aes.Encrypt(nonce, p.D, ctD, tag, ReadOnlySpan<byte>.Empty);
            CryptographicOperations.ZeroMemory(kek);

            // compute keyId = Base64(SHA256(pub))
            string keyId;
            using (var sha = SHA256.Create())
                keyId = Convert.ToBase64String(sha.ComputeHash(pub));

            // build key file object
            var kf = new KeyFile
            {
                Version = KeyFile.CurrentVersion,
                Algorithm = KeyFile.AlgP256,
                Aead = KeyFile.AeadAes256Gcm,
                Kdf = new KeyFileKdf
                {
                    Name = KeyFile.KdfPbkdf2Sha256,
                    SaltBase64 = Convert.ToBase64String(salt),
                    Iterations = iterations,
                    KeyLen = keyLen
                },
                EncSeed = new KeyFileEncSeed
                {
                    NonceBase64 = Convert.ToBase64String(nonce),
                    CiphertextBase64 = Convert.ToBase64String(ctD),
                    TagBase64 = Convert.ToBase64String(tag)
                },
                PublicKeyBase64 = Convert.ToBase64String(pub),
                KeyId = keyId,
                CreatedUtc = DateTime.UtcNow.ToString("O")
            };

            var baseName = keyName ?? $"ratsign_{SafeKeyIdSuffix(keyId)}";
            var outPath = Path.Combine(outputDirectory, $"{baseName}.sec.json");

            var json = JsonSerializer.Serialize(kf, new JsonSerializerOptions { WriteIndented = true });
            await File.WriteAllTextAsync(outPath, json, ct);

            CryptographicOperations.ZeroMemory(p.D);

            return outPath;
        }

        private static string SafeKeyIdSuffix(string keyIdBase64)
        {
            // produce a short, filename-safe suffix from the keyId
            // base64 can contain '/', '+', '='; map to hex first 8 bytes instead
            var raw = Convert.FromBase64String(keyIdBase64);
            var sb = new StringBuilder(16);
            for (int i = 0; i < Math.Min(8, raw.Length); i++)
                sb.Append(raw[i].ToString("x2"));

            return sb.ToString();
        }
    }
}
