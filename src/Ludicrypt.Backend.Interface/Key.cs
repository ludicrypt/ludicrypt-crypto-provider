namespace Ludicrypt.Backend.Interface;

public class Key : IKey
{
    public string Name { get; set; } = string.Empty;
    public string Algorithm { get; set; } = string.Empty;
    public string Identifier { get; set; } = string.Empty;
    public byte[]? PublicExponent { get; set; }
    public byte[]? Modulus { get; set; }
}
