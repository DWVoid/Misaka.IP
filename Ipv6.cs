namespace Misaka.IP;

public struct Ipv6Address : ISpanFormattable, IUtf8SpanFormattable
{
    private unsafe fixed byte _data[16];

    public unsafe Ipv6Address(ReadOnlySpan<byte> data)
    {
        fixed (byte* my = _data) data.CopyTo(new Span<byte>(my, 16));
    }

    public unsafe byte this[int i]
    {
        get => _data[i];
        set => _data[i] = value;
    }

    public unsafe ReadOnlySpan<byte> Span
    {
        get
        {
            fixed (byte* data = _data) return new ReadOnlySpan<byte>(data, 16);
        }
    }

    private unsafe (int, int) ScanZeroRange()
    {
        int offset = 0, length = 0, cursor = 0, rOffset = 0, rLength = 0;
        do
        {
            if ((_data[cursor << 1] | _data[(cursor << 1) | 1]) == 0)
            {
                if (length == 0)
                {
                    offset = cursor;
                    length = 1;
                }
                else ++length;

                if (cursor != 7) continue;
            }

            if (length <= 0) continue;
            if (length > rLength && length > 1)
            {
                rOffset = offset;
                rLength = length;
            }

            length = 0;
        } while (++cursor != 8);

        return (rOffset, rOffset + rLength - 1);
    }

    private static readonly byte[] HexTbl = "0123456789abcdef"u8.ToArray();

    /// <summary> Returns the string representation of this instance </summary>
    /// <returns> The string representation of this instance </returns>
    public override string ToString() => ToString(null, null);

    /// <inheritdoc/>
    public string ToString(string? format, IFormatProvider? formatProvider)
    {
        Span<char> buf = stackalloc char[39];
        TryFormat(buf, out var offset, ReadOnlySpan<char>.Empty, null);
        return buf[..offset].ToString();
    }

    /// <summary> Tries to format the value of the current instance into the provided span of characters. </summary>
    /// <param name="destination">The span in which to write this instance's value formatted as a span of characters. </param>
    /// <param name="charsWritten"> When this method returns, contains the number of characters that were written in <paramref name="destination" />. </param>
    /// <param name="format"> Ignored. </param>
    /// <param name="provider"> Ignored. </param>
    /// <returns> <see langword="true" /> if destination has at least 39 characters of space; otherwise, <see langword="false" />. </returns>
    public bool TryFormat(
        Span<char> destination, out int charsWritten,
        ReadOnlySpan<char> format, IFormatProvider? provider
    )
    {
        if (destination.Length < 39)
        {
            charsWritten = 0;
            return false;
        }

        charsWritten = FormatCore(destination);
        return true;
    }

    /// <summary> Tries to format the value of the current instance as UTF-8 into the provided span of bytes.</summary>
    /// <param name="utf8Destination"> The span in which to write this instance's value formatted as a span of bytes. </param>
    /// <param name="bytesWritten">When this method returns, contains the number of bytes that were written in <paramref name="utf8Destination" />.</param>
    /// <param name="format"> Ignored. </param>
    /// <param name="provider"> Ignored. </param>
    /// <returns> <see langword="true" /> if destination has at least 39 bytes of space; otherwise, <see langword="false" />. </returns>
    public bool TryFormat(
        Span<byte> utf8Destination, out int bytesWritten,
        ReadOnlySpan<char> format, IFormatProvider? provider
    )
    {
        if (utf8Destination.Length < 39)
        {
            bytesWritten = 0;
            return false;
        }

        bytesWritten = FormatCore(utf8Destination);
        return true;
    }

    private unsafe int FormatCore(Span<char> buf)
    {
        var offset = 0;
        var (sF, sL) = ScanZeroRange();
        for (var i = 0; i < 8; i++)
        {
            if (i < sF || i > sL)
            {
                int d = _data[i << 1];
                var h = d >> 4;
                if (h != 0) buf[offset++] = (char)HexTbl[h];
                h = d & 0xF;
                if (h != 0) buf[offset++] = (char)HexTbl[h];
                d = _data[(i << 1) | 1];
                h = d >> 4;
                if (h != 0) buf[offset++] = (char)HexTbl[h];
                h = d & 0xF;
                buf[offset++] = (char)HexTbl[h];
                if (i != 7) buf[offset++] = ':';
            }
            else if (i == sL)
            {
                if (sF == 0) buf[offset++] = ':';
                buf[offset++] = ':';
            }
        }

        return offset;
    }

    // exactly the same as the char variant, but with bytes
    private unsafe int FormatCore(Span<byte> buf)
    {
        var offset = 0;
        var (sF, sL) = ScanZeroRange();
        for (var i = 0; i < 8; i++)
        {
            if (i < sF || i > sL)
            {
                int d = _data[i << 1];
                var h = d >> 4;
                if (h != 0) buf[offset++] = HexTbl[h];
                h = d & 0xF;
                if (h != 0) buf[offset++] = HexTbl[h];
                d = _data[(i << 1) | 1];
                h = d >> 4;
                if (h != 0) buf[offset++] = HexTbl[h];
                h = d & 0xF;
                buf[offset++] = HexTbl[h];
                if (i != 7) buf[offset++] = (byte)':';
            }
            else if (i == sL)
            {
                if (sF == 0) buf[offset++] = (byte)':';
                buf[offset++] = (byte)':';
            }
        }

        return offset;
    }
}

public record struct Ipv6Header(
    byte Ver,
    byte TrafficClass,
    int FlowLabel,
    ushort PayloadLength,
    byte NextHeader,
    byte HopLimit,
    Ipv6Address SourceAddress,
    Ipv6Address DestinationAddress)
{
    /// <summary>
    /// Parse the header (without options) from packet.
    /// This is enough to determine routing target and data boundary.
    /// </summary>
    /// <param name="packet"> Packet data </param>
    /// <param name="header"> Parsed header </param>
    /// <returns>
    /// 0 if parse is successful; <br/>
    /// -1 if parse failed due to too few bytes (should not ever happen); <br/>
    /// </returns>
    public static int TryParse(ReadOnlySpan<byte> packet, out Ipv6Header header)
    {
        if (packet.Length >= 40)
        {
            header = new Ipv6Header
            (
                (byte)(packet[0] >> 4),
                (byte)(((packet[0] & 0xF) << 4) | (packet[1] >> 4)),
                ((packet[1] & 0xF) << 16) | (packet[2] << 8) | packet[3],
                (ushort)((packet[4] << 8) | packet[5]),
                packet[6],
                packet[7],
                new Ipv6Address(packet[8..24]),
                new Ipv6Address(packet[24..40])
            );
            return 0;
        }

        header = default;
        return -1;
    }

    /// <summary>
    /// Format the header (without options) into a packet.
    /// Fields are not validated and are formatted as-is.
    /// </summary>
    /// <param name="packet"> Packet data </param>
    /// <returns>
    /// 0 if parse is successful; <br/>
    /// -1 if parse failed due to too few bytes (should not ever happen); <br/>
    /// </returns>
    public int TryFormat(Span<byte> packet)
    {
        if (packet.Length < 40) return -1;
        unchecked
        {
            packet[0] = (byte)((Ver << 4) | (TrafficClass >> 4));
            packet[1] = (byte)((TrafficClass << 4) | ((FlowLabel >> 16) & 0xF));
            packet[2] = (byte)(FlowLabel >> 8);
            packet[3] = (byte)FlowLabel;
            packet[4] = (byte)(PayloadLength >> 8);
            packet[5] = (byte)PayloadLength;
            packet[6] = NextHeader;
            packet[7] = HopLimit;
        }

        SourceAddress.Span.CopyTo(packet[8..24]);
        DestinationAddress.Span.CopyTo(packet[24..40]);
        return 0;
    }
}