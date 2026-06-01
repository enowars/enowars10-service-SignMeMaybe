using System.Security.Cryptography;
using System.Text;

namespace SignMeMaybe.Security;

public static class Hashing
{
    public static string HashPassword(string password)
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
