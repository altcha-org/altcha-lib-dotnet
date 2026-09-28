using System.Globalization;
using System.Text;

namespace Altcha;

/// <summary>Formats doubles exactly like ECMAScript <c>Number.prototype.toString()</c>.</summary>
internal static class JsNumber
{
    public static string Format(double d)
    {
        if (double.IsNaN(d))
        {
            return "NaN";
        }

        if (double.IsInfinity(d))
        {
            return d > 0 ? "Infinity" : "-Infinity";
        }

        if (d == 0)
        {
            return "0";
        }

        // "R" yields the shortest round-trippable representation on .NET Core 3.0+.
        var r = Math.Abs(d).ToString("R", CultureInfo.InvariantCulture);
        var ePos = r.IndexOfAny(['E', 'e']);
        var mantissa = ePos >= 0 ? r[..ePos] : r;
        var exponent = ePos >= 0 ? int.Parse(r[(ePos + 1)..], NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture) : 0;

        var dot = mantissa.IndexOf('.');
        var intDigits = dot >= 0 ? dot : mantissa.Length;
        var digits = dot >= 0 ? mantissa.Remove(dot, 1) : mantissa;

        var leadingZeros = 0;
        while (leadingZeros < digits.Length && digits[leadingZeros] == '0')
        {
            leadingZeros++;
        }

        var s = digits[leadingZeros..].TrimEnd('0');
        var k = s.Length;
        var n = intDigits + exponent - leadingZeros;

        var sb = new StringBuilder(32);
        if (d < 0)
        {
            sb.Append('-');
        }

        if (k <= n && n <= 21)
        {
            sb.Append(s).Append('0', n - k);
        }
        else if (0 < n && n <= 21)
        {
            sb.Append(s, 0, n).Append('.').Append(s, n, k - n);
        }
        else if (-6 < n && n <= 0)
        {
            sb.Append("0.").Append('0', -n).Append(s);
        }
        else
        {
            sb.Append(s[0]);
            if (k > 1)
            {
                sb.Append('.').Append(s, 1, k - 1);
            }

            sb.Append('e').Append(n - 1 >= 0 ? '+' : '-').Append(Math.Abs(n - 1).ToString(CultureInfo.InvariantCulture));
        }

        return sb.ToString();
    }
}
