/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * 
 * Program:                         ratCORE.Signing.Signer
 * Description:                     Signs a file using a key file and the secret password and creates the signature file.
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
 * Filename:                        cls.ratCORE.Signing.Signer.cs
 * Language:                        C# (.NET 8)
 * Required:                        cls.ratCORE.Signing.KeyFile.cs, cls.ratCORE.Signing.SignatureFile.cs
 * Signing only:                    cls.ratCORE.Signing.Signer.cs, cls.ratCORE.Signing.KeyFile.cs, cls.ratCORE.Signing.SignatureFile.cs
 * Not required for signing only:   cls.ratCORE.Signing.KeyGen.cs, cls.ratCORE.Signing.Verifier.cs
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
    public sealed class Signer
    {
        private const int DLen = 32;
        private const int PubUncompressedLen = 65;

        /// <summary>Signs a file with an existing encrypted key file.</summary>
        /// <param name="inputFile">Path to the file to be signed.</param>
        /// <param name="keyFilePath">Path to the encrypted key file (.json).</param>
        /// <param name="password">Password to decrypt the seed.</param>
        /// <param name="outputSigPath">Path to the signature file output (.ratsig).</param>
        /// <param name="trustedComment">Optional comments (will be signed).</param>
        /// <returns></returns>
        public static async Task<string> SignFileAsync(
            string inputFile,
            string keyFilePath,
            string password,
            string? outputSigPath = null,
            string? trustedComment = null,
            CancellationToken ct = default)
        {
            // read key file
            var json = await File.ReadAllTextAsync(keyFilePath, ct);
            var keyFile = JsonSerializer.Deserialize<KeyFile>(json)
                            ?? throw new InvalidDataException("Invalid key file.");

            // expect ECDSA-P256
            if (!string.Equals(keyFile.Algorithm, "ecdsa-p256", StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException($"KeyFile.Algorithm='{keyFile.Algorithm}' - expect 'ecdsa-p256'.");

            // public key must be uncompressed point: 0x04 || X || Y
            var pub = Convert.FromBase64String(keyFile.PublicKeyBase64);
            if (pub.Length != PubUncompressedLen || pub[0] != 0x04)
                throw new InvalidDataException("Public key must be uncompressed EC point (65 bytes): 0x04||X(32)||Y(32).");

            var Qx = new byte[32];
            var Qy = new byte[32];
            Buffer.BlockCopy(pub, 1, Qx, 0, 32);
            Buffer.BlockCopy(pub, 33, Qy, 0, 32);

            // derive KEK via PBKDF2
            var salt = Convert.FromBase64String(keyFile.Kdf.SaltBase64);
            if (keyFile.Kdf.KeyLen != 32)
                throw new InvalidDataException("KDF keyLen must be 32 (AES-256).");
            
            var kek = Rfc2898DeriveBytes.Pbkdf2(
                Encoding.UTF8.GetBytes(password),
                salt,
                keyFile.Kdf.Iterations,
                HashAlgorithmName.SHA256,
                keyFile.Kdf.KeyLen);

            // decrypt private scalar D
            var nonce = Convert.FromBase64String(keyFile.EncSeed.NonceBase64);
            var ctSeed = Convert.FromBase64String(keyFile.EncSeed.CiphertextBase64);
            var tag = Convert.FromBase64String(keyFile.EncSeed.TagBase64);
            if (ctSeed.Length != DLen)
                throw new InvalidDataException("encSeed.ct must contain 32 bytes (private scalar D).");

            byte[] D = new byte[DLen];
            using (var aes = new AesGcm(kek, tagSizeInBytes: 16))
            {
                aes.Decrypt(nonce, ctSeed, tag, D, ReadOnlySpan<byte>.Empty);
            }
            CryptographicOperations.ZeroMemory(kek);

            // build ECDSA key from (Qx, Qy, D)
            var ecParams = new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = Qx, Y = Qy },
                D = D
            };
            using var ecdsa = ECDsa.Create(ecParams);
            CryptographicOperations.ZeroMemory(D);

            // hash file
            byte[] fileHash = await Sha256FileAsync(inputFile, ct);

            // message = hash || UTF8(comment) (comment is protected)
            byte[] message = trustedComment is { Length: > 0 }
                ? Combine(fileHash, Encoding.UTF8.GetBytes(trustedComment))
                : fileHash;

            // sign (DER-encoded ECDSA signature)
            byte[] signature = ecdsa.SignData(message, HashAlgorithmName.SHA256);

            // create signed object
            var sig = new SignatureFile
            {
                Magic = SignatureFile.MagicConst,
                Version = SignatureFile.CurrentVersion,
                Algorithm = SignatureFile.AlgP256,
                HashAlgorithm = SignatureFile.AlgSha256,
                PublicKeyBase64 = Convert.ToBase64String(pub),
                SignatureBase64 = Convert.ToBase64String(signature),
                TrustedComment = trustedComment,
                CreatedUtc = DateTime.UtcNow.ToString("O"),
                FileNameHint = Path.GetFileName(inputFile)
            };

            // save
            string outPath = outputSigPath ?? (inputFile + ".ratsig");
            var opts = new JsonSerializerOptions { WriteIndented = true };
            await File.WriteAllTextAsync(outPath, JsonSerializer.Serialize(sig, opts), ct);
            CryptographicOperations.ZeroMemory(fileHash);

            return outPath;
        }

        private static async Task<byte[]> Sha256FileAsync(string path, CancellationToken ct)
        {
            using var sha = SHA256.Create();
            await using var fs = File.OpenRead(path);
            var buffer = new byte[81920];
            int read;
            while ((read = await fs.ReadAsync(buffer.AsMemory(0, buffer.Length), ct)) > 0)
            {
                sha.TransformBlock(buffer, 0, read, null, 0);
            }
            sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
            return sha.Hash!;
        }

        private static byte[] Combine(byte[] a, byte[] b)
        {
            var r = new byte[a.Length + b.Length];
            Buffer.BlockCopy(a, 0, r, 0, a.Length);
            Buffer.BlockCopy(b, 0, r, a.Length, b.Length);
            return r;
        }
    }
}
