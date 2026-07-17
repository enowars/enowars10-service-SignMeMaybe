using System.Numerics;

namespace SignMeMaybe.Signing;

public readonly record struct EcPoint(BigInteger X, BigInteger Y, bool IsInfinity = false)
{
    public static EcPoint Infinity { get; } = new(BigInteger.Zero, BigInteger.Zero, true);
}

public sealed record EcCurve(
    string Name,
    BigInteger P,
    BigInteger A,
    BigInteger B,
    EcPoint Generator,
    BigInteger Order,
    BigInteger Cofactor)
{
    public bool IsInField(EcPoint point)
    {
        return !point.IsInfinity
            && point.X >= BigInteger.Zero
            && point.X < P
            && point.Y >= BigInteger.Zero
            && point.Y < P;
    }

    public bool IsOnCurve(EcPoint point)
    {
        if (!IsInField(point))
        {
            return false;
        }

        var left = Mod(point.Y * point.Y);
        var right = Mod(point.X * point.X * point.X + A * point.X + B);
        return left == right;
    }

    public EcPoint Add(EcPoint left, EcPoint right)
    {
        if (left.IsInfinity)
        {
            return right;
        }

        if (right.IsInfinity)
        {
            return left;
        }

        if (left.X == right.X && Mod(left.Y + right.Y) == BigInteger.Zero)
        {
            return EcPoint.Infinity;
        }

        BigInteger slope;
        if (left == right)
        {
            if (Mod(left.Y) == BigInteger.Zero)
            {
                return EcPoint.Infinity;
            }

            slope = Mod((3 * left.X * left.X + A) * Inverse(2 * left.Y));
        }
        else
        {
            slope = Mod((right.Y - left.Y) * Inverse(right.X - left.X));
        }

        var x = Mod(slope * slope - left.X - right.X);
        var y = Mod(slope * (left.X - x) - left.Y);
        return new EcPoint(x, y);
    }

    public EcPoint Multiply(BigInteger scalar, EcPoint point)
    {
        var result = EcPoint.Infinity;
        var addend = point;

        while (scalar > BigInteger.Zero)
        {
            if (!scalar.IsEven)
            {
                result = Add(result, addend);
            }

            addend = Add(addend, addend);
            scalar >>= 1;
        }

        return result;
    }

    public BigInteger Mod(BigInteger value)
    {
        var result = value % P;
        return result.Sign < 0 ? result + P : result;
    }

    private BigInteger Inverse(BigInteger value)
    {
        return BigInteger.ModPow(Mod(value), P - 2, P);
    }

    public static BigInteger ParseHex(string value)
    {
        value = value.Trim();
        if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            value = value[2..];
        }

        if (value.Length == 0)
        {
            throw new FormatException("hex value must not be empty");
        }

        if (value.Length % 2 != 0)
        {
            value = "0" + value;
        }

        var bytes = Convert.FromHexString(value);
        return new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
    }

    public static string ToHex(BigInteger value, int minBytes = 0)
    {
        if (value.Sign < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(value), "value must be unsigned");
        }

        var bytes = value.ToByteArray(isUnsigned: true, isBigEndian: true);
        if (bytes.Length == 0)
        {
            bytes = [0];
        }

        if (bytes.Length < minBytes)
        {
            var padded = new byte[minBytes];
            Buffer.BlockCopy(bytes, 0, padded, minBytes - bytes.Length, bytes.Length);
            bytes = padded;
        }

        return "0x" + Convert.ToHexString(bytes).ToLowerInvariant();
    }

    public static string ToFixedHex(BigInteger value, int bytes)
    {
        return ToHex(value, bytes)[2..];
    }
}

public static class SigningCurves
{
    private const string P256OrderHex = "0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";

    public const string DefaultCurveName = "P-256";
    public const int PrivateScalarBytes = 32;
    public static readonly BigInteger PrivateScalarLimit = EcCurve.ParseHex(P256OrderHex);

    private static readonly IReadOnlyDictionary<string, EcCurve> CurvesByName = CreateCurves()
        .ToDictionary(curve => curve.Name, StringComparer.OrdinalIgnoreCase);

    public static IReadOnlyCollection<EcCurve> All => CurvesByName.Values.ToArray();

    public static EcCurve Default => CurvesByName[DefaultCurveName];

    public static bool TryGet(string name, out EcCurve curve)
    {
        return CurvesByName.TryGetValue(name, out curve!);
    }

    public static object ToPublicCurve(EcCurve curve)
    {
        return new
        {
            name = curve.Name,
            equation = "short-weierstrass",
            p = EcCurve.ToHex(curve.P),
            a = EcCurve.ToHex(curve.A),
            b = EcCurve.ToHex(curve.B),
            g = ToPublicPoint(curve.Generator),
            n = EcCurve.ToHex(curve.Order),
            h = EcCurve.ToHex(curve.Cofactor)
        };
    }

    public static object ToPublicPoint(EcPoint point)
    {
        if (point.IsInfinity)
        {
            return new { infinity = true };
        }

        return new
        {
            x = EcCurve.ToHex(point.X),
            y = EcCurve.ToHex(point.Y)
        };
    }

    private static IEnumerable<EcCurve> CreateCurves()
    {
        yield return new EcCurve(
            DefaultCurveName,
            EcCurve.ParseHex("0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff"),
            EcCurve.ParseHex("0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc"),
            EcCurve.ParseHex("0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"),
            new EcPoint(
                EcCurve.ParseHex("0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
                EcCurve.ParseHex("0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")),
            PrivateScalarLimit,
            BigInteger.One);
    }
}
