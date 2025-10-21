/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * 
 * Program:                         ratCORE.Signing.Verifier
 * Description:                     Verifies a file using its signature file and its public key or key id for trust check.
 * Current Version:                 1.0.9421.1309 (17.10.2025)
 * Company:                         ratware
 * Author:                          Tom V. (ratware)
 * Email:                           info@ratware.de
 * Copyright:                       © 2025 ratware
 * License:                         Creative Commons Attribution 4.0 International (CC BY 4.0)
 * License URL:                     https://creativecommons.org/licenses/by/4.0/
 * Filename:                        cls.ratCORE.Signing.Verifier.cs
 * Language:                        C# (.NET 8)
 * Required:                        cls.ratCORE.Signing.SignatureFile.cs
 * Verify only:                     cls.ratCORE.Signing.Verifier.cs, cls.ratCORE.Signing.SignatureFile.cs
 * Not required for verify only:    cls.ratCORE.Signing.KeyGen.cs, cls.ratCORE.Signing.KeyFile.cs, cls.ratCORE.Signing.Signer.cs
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
    public sealed class Verifier
    {
        private const int PubUncompressedLen = 65;

        /// <summary>Verifies a file with the associated signature file.</summary>
        /// <param name="inputFile">Path to the file to be verified.</param>
        /// <param name="signaturePath">Path to the signature file (.ratsig).</param>
        /// <param name="expectedPublicKeyBase64">Expected public key. Trust check!</param>
        public static async Task<bool> VerifyFileWithPublicKeyAsync(
            string inputFile,
            string signaturePath,
            string expectedPublicKeyBase64,
            CancellationToken ct = default)
        {
            var (ok, sigPubB64) = await VerifyCoreAsync(inputFile, signaturePath, ct);
            if (!ok) return false;

            // trust check: check expected public key (constant time)
            var a = Convert.FromBase64String(sigPubB64);
            var b = Convert.FromBase64String(expectedPublicKeyBase64);
            if (a.Length != b.Length) return false;
            return CryptographicOperations.FixedTimeEquals(a, b);
        }

        /// <summary>Verifies a file with the associated signature file.</summary>
        /// <param name="inputFile">Path to the file to be verified.</param>
        /// <param name="signaturePath">Path to the signature file (.ratsig).</param>
        /// <param name="expectedKeyIdBase64">Expected key id. Trust check!</param>
        public static async Task<bool> VerifyFileWithKeyIdAsync(
            string inputFile,
            string signaturePath,
            string expectedKeyIdBase64,
            CancellationToken ct = default)
        {
            var (ok, sigPubB64) = await VerifyCoreAsync(inputFile, signaturePath, ct);
            if (!ok) return false;

            var keyId = ComputeKeyIdBase64(Convert.FromBase64String(sigPubB64));
            // KeyId is short, comparison as string is sufficient; if you like, you can use bytes
            return string.Equals(keyId, expectedKeyIdBase64, StringComparison.Ordinal);
        }

        /// <summary>Verifies a file with the associated signature file.</summary>
        /// <param name="inputFile">Path to the file to be verified.</param>
        /// <param name="signaturePath">Path to the signature file (.ratsig).</param>
        public static async Task<bool> VerifyFileAsync(
            string inputFile, 
            string signaturePath, 
            CancellationToken ct = default)
        {
            var (ok, _) = await VerifyCoreAsync(inputFile, signaturePath, ct);
            return ok;
        }

        private static async Task<(bool ok, string sigPublicKeyBase64)> VerifyCoreAsync(
            string inputFile,
            string signaturePath,
            CancellationToken ct = default)
        {
            // load signature file and check base
            var sigJson = await File.ReadAllTextAsync(signaturePath, ct);
            var sig = JsonSerializer.Deserialize<SignatureFile>(sigJson)
                ?? throw new InvalidDataException("Invalid signature file.");

            if (!string.Equals(sig.Magic, SignatureFile.MagicConst, StringComparison.Ordinal)
                || sig.Version != SignatureFile.CurrentVersion)
                throw new InvalidDataException("Incompatible signature format.");

            if (!string.Equals(sig.Algorithm, SignatureFile.AlgP256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException($"Algorithm '{sig.Algorithm}' is not supported (expects '{SignatureFile.AlgP256}').");

            if (!string.Equals(sig.HashAlgorithm, SignatureFile.AlgSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException($"Hash algorithm '{sig.HashAlgorithm}' is not supported (expects '{SignatureFile.AlgSha256}').");

            // read public key as uncompressed EC-Point (0x04||X||Y)
            var pub = Convert.FromBase64String(sig.PublicKeyBase64);
            if (pub.Length != PubUncompressedLen || pub[0] != 0x04)
                throw new InvalidDataException("PublicKey must be uncompressed EC-Point (65 bytes): 0x04||X(32)||Y(32).");

            var Qx = new byte[32];
            var Qy = new byte[32];
            Buffer.BlockCopy(pub, 1, Qx, 0, 32);
            Buffer.BlockCopy(pub, 33, Qy, 0, 32);

            // hash file
            byte[] fileHash = await Sha256FileAsync(inputFile, ct);

            // message = hash || UTF8(comment) (comment is protected)
            byte[] message = sig.TrustedComment is { Length: > 0 }
                ? Combine(fileHash, Encoding.UTF8.GetBytes(sig.TrustedComment))
                : fileHash;

            // build ECDSA key from (Qx, Qy)
            var ecParams = new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = Qx, Y = Qy }
            };
            using var ecdsa = ECDsa.Create(ecParams);

            // verify signature (DER)
            var signature = Convert.FromBase64String(sig.SignatureBase64);
            bool ok = ecdsa.VerifyData(message, signature, HashAlgorithmName.SHA256);
            CryptographicOperations.ZeroMemory(fileHash);

            return (ok, sig.PublicKeyBase64);
        }

        private static async Task<byte[]> Sha256FileAsync(string path, CancellationToken ct)
        {
            using var sha = SHA256.Create();
            await using var fs = File.OpenRead(path);
            var buffer = new byte[81920];
            int read;
            while ((read = await fs.ReadAsync(buffer.AsMemory(0, buffer.Length), ct)) > 0)
                sha.TransformBlock(buffer, 0, read, null, 0);
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

        private static string ComputeKeyIdBase64(byte[] pubUncompressed)
        {
            using var sha = SHA256.Create();
            return Convert.ToBase64String(sha.ComputeHash(pubUncompressed));
        }
    }
}
