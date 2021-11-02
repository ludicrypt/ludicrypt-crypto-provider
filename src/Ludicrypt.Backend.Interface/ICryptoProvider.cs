namespace Ludicrypt.Backend.Interface;

public interface ICryptoProvider
{
    IKey GetKey(string keyName);
    IKey CreateKey(string keyName, string algorithm);
    void DeleteKey(string keyIdentifier);

    //void ImportKey();
    //void ExportKey();
    byte[] Encrypt(string keyIdentifier, byte[] input);
    byte[] Decrypt(string keyIdentifier, byte[] input);
    byte[] SignHash(string keyIdentifier, byte[] hash);
    bool VerifySignature(string keyIdentifier, byte[] hash, byte[] signature);
    //void WrapKey();
    //void UnwrapKey();
}
