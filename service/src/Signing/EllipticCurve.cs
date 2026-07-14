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
    public const string DefaultCurveName = "civic-archive-p256k";
    public const int PrivateScalarBytes = 6;
    public static readonly BigInteger PrivateScalarLimit = BigInteger.One << (PrivateScalarBytes * 8);

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
            EcCurve.ParseHex("0x10001"),
            EcCurve.ParseHex("0x02"),
            EcCurve.ParseHex("0x03"),
            new EcPoint(EcCurve.ParseHex("0x02"), EcCurve.ParseHex("0xa4bc")),
            EcCurve.ParseHex("0xff6a"),
            BigInteger.One);

        yield return new EcCurve(
            "registry-ledger-p257",
            EcCurve.ParseHex("0x10001"),
            EcCurve.ParseHex("0x05"),
            EcCurve.ParseHex("0x07"),
            new EcPoint(EcCurve.ParseHex("0x01"), EcCurve.ParseHex("0xcd7f")),
            EcCurve.ParseHex("0x8093"),
            BigInteger.One);

        yield return new EcCurve(
            "P-224",
            EcCurve.ParseHex("0xffffffffffffffffffffffffffffffff000000000000000000000001"),
            EcCurve.ParseHex("0xfffffffffffffffffffffffffffffffefffffffffffffffffffffffe"),
            EcCurve.ParseHex("0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4"),
            new EcPoint(
                EcCurve.ParseHex("0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21"),
                EcCurve.ParseHex("0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34")),
            EcCurve.ParseHex("0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d"),
            BigInteger.One);
    }
}
