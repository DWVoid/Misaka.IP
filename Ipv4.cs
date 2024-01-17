namespace Misaka.IP;

[Flags]
public enum Ipv4Flag : byte
{
    DF = 2,
    MF = 4
}

public struct Ipv4Address : ISpanFormattable, IUtf8SpanFormattable
{
    private unsafe fixed byte _data[4];

    private unsafe Ipv4Address(byte a, byte b, byte c, byte d)
    {
        _data[0] = a;
        _data[1] = b;
        _data[2] = c;
        _data[3] = d;
    }

    public Ipv4Address(ReadOnlySpan<byte> data) : this(data[0], data[1], data[2], data[3])
    {
    }

    public unsafe byte this[int i]
    {
        get => _data[i];
        set => _data[i] = value;
    }

    public unsafe uint Value => (uint)((_data[0] << 24) | (_data[1] << 16) | (_data[2] << 8) | _data[3]);

    public unsafe ReadOnlySpan<byte> Span
    {
        get
        {
            fixed (byte* data = _data) return new ReadOnlySpan<byte>(data, 4);
        }
    }

    /// <summary> Returns the string representation of this instance </summary>
    /// <returns> The string representation of this instance </returns>
    public override string ToString() => ToString(null, null);

    /// <inheritdoc/>
    public string ToString(string? format, IFormatProvider? formatProvider)
    {
        Span<char> buf = stackalloc char[15];
        TryFormat(buf, out var offset, ReadOnlySpan<char>.Empty, null);
        return buf[..offset].ToString();
    }

    /// <summary> Tries to format the value of the current instance into the provided span of characters. </summary>
    /// <param name="destination">The span in which to write this instance's value formatted as a span of characters. </param>
    /// <param name="charsWritten"> When this method returns, contains the number of characters that were written in <paramref name="destination" />. </param>
    /// <param name="format"> Ignored. </param>
    /// <param name="provider"> Ignored. </param>
    /// <returns> <see langword="true" /> if destination has at least 15 characters of space; otherwise, <see langword="false" />. </returns>
    public bool TryFormat(
        Span<char> destination, out int charsWritten,
        ReadOnlySpan<char> format, IFormatProvider? provider
    )
    {
        if (destination.Length < 15)
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
    /// <returns> <see langword="true" /> if destination has at least 15 bytes of space; otherwise, <see langword="false" />. </returns>
    public bool TryFormat(
        Span<byte> utf8Destination, out int bytesWritten,
        ReadOnlySpan<char> format, IFormatProvider? provider
    )
    {
        if (utf8Destination.Length < 15)
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
        _data[0].TryFormat(buf[offset..], out var forward);
        offset += forward;
        buf[offset++] = '.';
        _data[1].TryFormat(buf[offset..], out forward);
        offset += forward;
        buf[offset++] = '.';
        _data[2].TryFormat(buf[offset..], out forward);
        offset += forward;
        buf[offset++] = '.';
        _data[3].TryFormat(buf[offset..], out forward);
        offset += forward;
        return offset;
    }

    // exactly the same as the char variant, but with bytes
    private unsafe int FormatCore(Span<byte> buf)
    {
        var offset = 0;
        _data[0].TryFormat(buf[offset..], out var forward);
        offset += forward;
        buf[offset++] = (byte)'.';
        _data[1].TryFormat(buf[offset..], out forward);
        offset += forward;
        buf[offset++] = (byte)'.';
        _data[2].TryFormat(buf[offset..], out forward);
        offset += forward;
        buf[offset++] = (byte)'.';
        _data[3].TryFormat(buf[offset..], out forward);
        offset += forward;
        return offset;
    }
}

public record struct Ipv4Header(
    byte Ver,
    byte IHL,
    byte DSCP,
    byte ECN,
    ushort TotalLength,
    ushort Identification,
    Ipv4Flag Flags,
    ushort FragmentOffset,
    byte TimeToLive,
    byte Protocol,
    ushort Checksum,
    Ipv4Address SourceAddress,
    Ipv4Address DestinationAddress)
{
    /// <summary>
    /// Parse the header (without options) from packet.
    /// This is enough to determine routing target and data boundary
    /// </summary>
    /// <param name="packet"> Packet data </param>
    /// <param name="header"> Parsed header </param>
    /// <returns>
    /// 0 if parse is successful; <br/>
    /// -1 if parse failed due to too few bytes (should not ever happen); <br/>
    /// -2 if parse failed due to checksum fail (TODO) 
    /// </returns>
    public static int TryParse(ReadOnlySpan<byte> packet, out Ipv4Header header)
    {
        if (packet.Length >= 20)
        {
            header = new Ipv4Header
            (
                (byte)(packet[0] >> 4),
                (byte)(packet[0] & 0xF),
                (byte)(packet[1] >> 2),
                (byte)(packet[1] & 0x3),
                (ushort)((packet[2] << 8) | packet[3]),
                (ushort)((packet[4] << 8) | packet[5]),
                (Ipv4Flag)(packet[6] >> 5),
                (ushort)(((packet[6] & 0b11111) << 8) | packet[7]),
                packet[8],
                packet[9],
                (ushort)((packet[10] << 8) | packet[11]),
                new Ipv4Address(packet[12..16]),
                new Ipv4Address(packet[16..20])
            );
            // TODO: checksum
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
            packet[0] = (byte)((Ver << 4) | (IHL >> 4));
            packet[1] = (byte)((DSCP << 2) | (ECN & 0x3));
            packet[2] = (byte)(TotalLength >> 8);
            packet[3] = (byte)TotalLength;
            packet[4] = (byte)(Identification >> 8);
            packet[5] = (byte)Identification;
            packet[6] = (byte)(((int)Flags << 5) | ((FragmentOffset >> 8) & 0b11111));
            packet[7] = (byte)FragmentOffset;
            packet[8] = TimeToLive;
            packet[9] = Protocol;
            packet[10] = (byte)(Checksum >> 8);
            packet[11] = (byte)Checksum;
        }

        SourceAddress.Span.CopyTo(packet[12..16]);
        DestinationAddress.Span.CopyTo(packet[16..20]);
        return 0;
    }
}