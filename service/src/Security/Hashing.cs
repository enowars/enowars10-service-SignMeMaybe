using System.Security.Cryptography;
using System.Text;

namespace SignMeMaybe.Security;

public static class Hashing
{
    private const int Pbkdf2Iterations = 210_000;
    private const int Pbkdf2SaltBytes = 16;
    private const int Pbkdf2HashBytes = 32;
    private const string Pbkdf2Prefix = "pbkdf2-sha256";

    public static string HashPassword(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(Pbkdf2SaltBytes);
        var hash = Rfc2898DeriveBytes.Pbkdf2(
            password,
            salt,
            Pbkdf2Iterations,
            HashAlgorithmName.SHA256,
            Pbkdf2HashBytes);

        return string.Join(
            "$",
            Pbkdf2Prefix,
            Pbkdf2Iterations.ToString(System.Globalization.CultureInfo.InvariantCulture),
            Convert.ToHexString(salt).ToLowerInvariant(),
            Convert.ToHexString(hash).ToLowerInvariant());
    }

    public static bool VerifyPassword(string password, string storedHash, out bool needsUpgrade)
    {
        needsUpgrade = false;

        if (TryVerifyPbkdf2(password, storedHash))
        {
            return true;
        }

        if (IsLegacyHash(storedHash)
            && FixedTimeEquals(storedHash, LegacyHashPassword(password)))
        {
            needsUpgrade = true;
            return true;
        }

        return false;
    }

    private static bool TryVerifyPbkdf2(string password, string storedHash)
    {
        var parts = storedHash.Split('$', StringSplitOptions.TrimEntries);
        if (parts.Length != 4
            || !string.Equals(parts[0], Pbkdf2Prefix, StringComparison.Ordinal)
            || !int.TryParse(parts[1], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var iterations)
            || iterations <= 0)
        {
            return false;
        }

        try
        {
            var salt = Convert.FromHexString(parts[2]);
            var expected = Convert.FromHexString(parts[3]);
            if (salt.Length < Pbkdf2SaltBytes || expected.Length == 0)
            {
                return false;
            }

            var actual = Rfc2898DeriveBytes.Pbkdf2(
                password,
                salt,
                iterations,
                HashAlgorithmName.SHA256,
                expected.Length);

            return CryptographicOperations.FixedTimeEquals(actual, expected);
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static bool IsLegacyHash(string storedHash)
    {
        return storedHash.Length == 64 && storedHash.All(Uri.IsHexDigit);
    }

    private static string LegacyHashPassword(string password)
    {
        return Sha256Hex(Encoding.UTF8.GetBytes("SignMeMaybe::" + password));
    }

    public static string Sha256Hex(byte[] bytes)
    {
        return Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    }

    public static bool FixedTimeEquals(string leftHex, string rightHex)
    {
        var leftBytes = Encoding.UTF8.GetBytes(leftHex);
        var rightBytes = Encoding.UTF8.GetBytes(rightHex);

        return leftBytes.Length == rightBytes.Length
            && CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes);
    }
}
