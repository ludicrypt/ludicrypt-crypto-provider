namespace Ludicrypt.Backend.Interface;

public interface IKey
{
    string Name { get; }
    string Algorithm { get; }
    string Identifier { get; }
    byte[]? PublicExponent { get; }
    byte[]? Modulus { get; }
}
