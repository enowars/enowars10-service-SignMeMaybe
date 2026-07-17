using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace SignMeMaybe.Signing;

public static class SigningSecretBox
{
    private const int DefaultProfileKeyBits = 96;
    private const int DefaultProfileKeyBytes = DefaultProfileKeyBits / 8;

    public static string Encrypt(string authorityId, EcCurve curve, BigInteger scalar, string secret)
    {
        var nonce = RandomNumberGenerator.GetBytes(12);
        var plaintext = Encoding.UTF8.GetBytes(secret);
        var ciphertext = XorWithStream(authorityId, DeriveProfileScalar(curve, scalar), curve.ScalarBytes, nonce, plaintext);
        return $"v1:{Convert.ToHexString(nonce).ToLowerInvariant()}:{Convert.ToHexString(ciphertext).ToLowerInvariant()}";
    }

    public static string Decrypt(string authorityId, EcCurve curve, BigInteger scalar, string blob)
    {
        var parts = blob.Split(':', StringSplitOptions.TrimEntries);
        if (parts.Length != 3 || parts[0] != "v1")
        {
            throw new FormatException("unsupported signing secret blob");
        }

        var nonce = Convert.FromHexString(parts[1]);
        var ciphertext = Convert.FromHexString(parts[2]);
        var plaintext = XorWithStream(authorityId, DeriveProfileScalar(curve, scalar), curve.ScalarBytes, nonce, ciphertext);
        return Encoding.UTF8.GetString(plaintext);
    }

    public static BigInteger CreatePrivateScalar(EcCurve curve)
    {
        var bytes = new byte[ProfileScalarBytes(curve)];
        BigInteger scalar;
        do
        {
            RandomNumberGenerator.Fill(bytes);
            scalar = new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
        }
        while (scalar <= BigInteger.Zero || scalar >= curve.Order);

        return scalar;
    }

    public static string CreatePublicId(string prefix)
    {
        return prefix + Convert.ToBase64String(RandomNumberGenerator.GetBytes(18))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    private static byte[] XorWithStream(string authorityId, BigInteger scalar, int scalarBytes, byte[] nonce, byte[] input)
    {
        var output = new byte[input.Length];
        var offset = 0;
        var counter = 0;
        var scalarHex = EcCurve.ToFixedHex(scalar, scalarBytes);
        var nonceHex = Convert.ToHexString(nonce).ToLowerInvariant();

        while (offset < input.Length)
        {
            var material = Encoding.UTF8.GetBytes(
                $"SignMeMaybe signing secret:{authorityId}:{scalarHex}:{nonceHex}:{counter}");
            var block = SHA256.HashData(material);
            var take = Math.Min(block.Length, input.Length - offset);

            for (var index = 0; index < take; index++)
            {
                output[offset + index] = (byte)(input[offset + index] ^ block[index]);
            }

            offset += take;
            counter++;
        }

        return output;
    }

    private static BigInteger DeriveProfileScalar(EcCurve curve, BigInteger scalar)
    {
        return string.Equals(curve.Name, SigningCurves.DefaultCurveName, StringComparison.OrdinalIgnoreCase)
            ? scalar & ((BigInteger.One << DefaultProfileKeyBits) - BigInteger.One)
            : scalar;
    }

    private static int ProfileScalarBytes(EcCurve curve)
    {
        return string.Equals(curve.Name, SigningCurves.DefaultCurveName, StringComparison.OrdinalIgnoreCase)
            ? DefaultProfileKeyBytes
            : curve.ScalarBytes;
    }
}
