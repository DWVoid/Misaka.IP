namespace Misaka.IP;

public enum IpVersion
{
    Ipv4,
    Ipv6,
    Unknown
}

public static class Ip
{
    public static IpVersion GetVersion(ReadOnlySpan<byte> packet)
    {
        if (!packet.IsEmpty)
            return (packet[0] & 0xF0) switch
            {
                0x40 => IpVersion.Ipv4,
                0x60 => IpVersion.Ipv6,
                _ => IpVersion.Unknown
            };
        throw new ArgumentException("empty packet");
    }
}