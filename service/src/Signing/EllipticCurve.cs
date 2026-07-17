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
    public int ScalarBytes => Order.ToByteArray(isUnsigned: true, isBigEndian: true).Length;

    private readonly record struct JacobianPoint(BigInteger X, BigInteger Y, BigInteger Z, bool IsInfinity = false)
    {
        public static JacobianPoint Infinity { get; } = new(BigInteger.Zero, BigInteger.One, BigInteger.Zero, true);
    }

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
        if (scalar <= BigInteger.Zero || point.IsInfinity)
        {
            return EcPoint.Infinity;
        }

        var result = JacobianPoint.Infinity;
        var scalarBytes = scalar.ToByteArray(isUnsigned: true, isBigEndian: true);

        foreach (var scalarByte in scalarBytes)
        {
            for (var bit = 7; bit >= 0; bit--)
            {
                result = DoubleJacobian(result);
                if (((scalarByte >> bit) & 1) != 0)
                {
                    result = AddMixed(result, point);
                }
            }
        }

        return ToAffine(result);
    }

    public BigInteger Mod(BigInteger value)
    {
        var result = value % P;
        return result.Sign < 0 ? result + P : result;
    }

    private JacobianPoint FromAffine(EcPoint point)
    {
        return point.IsInfinity
            ? JacobianPoint.Infinity
            : new JacobianPoint(Mod(point.X), Mod(point.Y), BigInteger.One);
    }

    private EcPoint ToAffine(JacobianPoint point)
    {
        if (point.IsInfinity || point.Z.IsZero)
        {
            return EcPoint.Infinity;
        }

        var zInverse = Inverse(point.Z);
        var zInverseSquared = Mod(zInverse * zInverse);
        var x = Mod(point.X * zInverseSquared);
        var y = Mod(point.Y * zInverseSquared * zInverse);
        return new EcPoint(x, y);
    }

    private JacobianPoint DoubleJacobian(JacobianPoint point)
    {
        if (point.IsInfinity || point.Y.IsZero)
        {
            return JacobianPoint.Infinity;
        }

        var xx = Mod(point.X * point.X);
        var yy = Mod(point.Y * point.Y);
        var yyyy = Mod(yy * yy);
        var zz = Mod(point.Z * point.Z);
        var s = Mod(2 * (Mod((point.X + yy) * (point.X + yy)) - xx - yyyy));
        var m = Mod(3 * xx + A * Mod(zz * zz));
        var t = Mod(m * m - 2 * s);
        var x = t;
        var y = Mod(m * (s - t) - 8 * yyyy);
        var z = Mod((point.Y + point.Z) * (point.Y + point.Z) - yy - zz);
        return new JacobianPoint(x, y, z);
    }

    private JacobianPoint AddMixed(JacobianPoint left, EcPoint right)
    {
        if (left.IsInfinity)
        {
            return FromAffine(right);
        }

        if (right.IsInfinity)
        {
            return left;
        }

        var z1z1 = Mod(left.Z * left.Z);
        var u2 = Mod(right.X * z1z1);
        var s2 = Mod(right.Y * left.Z * z1z1);
        var h = Mod(u2 - left.X);
        var r = Mod(2 * (s2 - left.Y));

        if (h.IsZero)
        {
            return r.IsZero ? DoubleJacobian(left) : JacobianPoint.Infinity;
        }

        var hh = Mod(h * h);
        var i = Mod(4 * hh);
        var j = Mod(h * i);
        var v = Mod(left.X * i);
        var x = Mod(r * r - j - 2 * v);
        var y = Mod(r * (v - x) - 2 * left.Y * j);
        var z = Mod((left.Z + h) * (left.Z + h) - z1z1 - hh);

        return new JacobianPoint(x, y, z);
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
    public const string DefaultCurveName = "P-256";

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
            EcCurve.ParseHex("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
            BigInteger.One);

        yield return new EcCurve(
            "P-384",
            EcCurve.ParseHex("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff"),
            EcCurve.ParseHex("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc"),
            EcCurve.ParseHex("0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef"),
            new EcPoint(
                EcCurve.ParseHex("0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7"),
                EcCurve.ParseHex("0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f")),
            EcCurve.ParseHex("0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973"),
            BigInteger.One);

        yield return new EcCurve(
            "brainpoolP256r1",
            EcCurve.ParseHex("0xa9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377"),
            EcCurve.ParseHex("0x7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9"),
            EcCurve.ParseHex("0x26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6"),
            new EcPoint(
                EcCurve.ParseHex("0x8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262"),
                EcCurve.ParseHex("0x547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997")),
            EcCurve.ParseHex("0xa9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7"),
            BigInteger.One);

        yield return new EcCurve(
            "brainpoolP384r1",
            EcCurve.ParseHex("0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53"),
            EcCurve.ParseHex("0x7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826"),
            EcCurve.ParseHex("0x04a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57cb4390295dbc9943ab78696fa504c11"),
            new EcPoint(
                EcCurve.ParseHex("0x1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e"),
                EcCurve.ParseHex("0x8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c5315")),
            EcCurve.ParseHex("0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565"),
            BigInteger.One);
    }
}
