using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using Ludicrypt.Backend.Interface;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Console;
using Microsoft.Extensions.Logging.Debug;

namespace Ludicrypt.Backend.AzureKeyVault;

public class AzureKeyVaultProvider : ICryptoProvider
{
    private readonly ILogger<AzureKeyVaultProvider> _logger;
    private readonly TokenCredential _credential = new DefaultAzureCredential();
    private readonly KeyClient _keyClient;

    public AzureKeyVaultProvider()
    {
        var loggerFactory = LoggerFactory.Create(logging =>
        {
            logging.AddDebug();
            logging.AddConsole();
            logging.AddFilter<DebugLoggerProvider>(null, LogLevel.Debug);
            logging.AddFilter<ConsoleLoggerProvider>(null, LogLevel.Debug);
        });

        _logger = loggerFactory.CreateLogger<AzureKeyVaultProvider>();

        _keyClient = new KeyClient(new Uri(Environment.GetEnvironmentVariable("LUDICRYPT_BACKEND_AZUREKEYVAULT_VAULTURI")!), _credential);
    }

    //public AzureKeyVaultProvider(ILoggerFactory loggerFactory)
    //{
    //    _logger = loggerFactory.CreateLogger<AzureKeyVaultProvider>();
    //
    //    _keyClient = new KeyClient(new Uri(_keyVaultName), _credential);
    //}

    public IKey GetKey(string keyName)
    {
        _logger.LogInformation("GetKey()");

        var key = _keyClient.GetKey(keyName);

        return new Key
        {
            Name = key.Value.Name,
            Algorithm = key.Value.KeyType.ToString(),
            Identifier = key.Value.Id.ToString(),
            PublicExponent = key.Value.Key.E,
            Modulus = key.Value.Key.N
        };
    }

    public IKey CreateKey(string keyName, string algorithm)
    {
        _logger.LogInformation("CreateKey()");

        var key = _keyClient.CreateKey(keyName, KeyType.Rsa);

        return new Key
        {
            Name = key.Value.Name,
            Algorithm = key.Value.KeyType.ToString(),
            Identifier = key.Value.Id.ToString()
        };
    }

    public void DeleteKey(string keyName)
    {
        _logger.LogInformation("DeleteKey()");

        _keyClient.StartDeleteKey(keyName);
    }

    public byte[] Encrypt(string keyIdentifier, byte[] input)
    {
        _logger.LogInformation("Encrypt()");

        var cryptoClient = new CryptographyClient(new Uri(keyIdentifier), _credential);

        var result = cryptoClient.Encrypt(EncryptionAlgorithm.RsaOaep256, input);

        return result.Ciphertext;
    }

    public byte[] Decrypt(string keyIdentifier, byte[] input)
    {
        _logger.LogInformation("Decrypt()");

        var cryptoClient = new CryptographyClient(new Uri(keyIdentifier), _credential);

        var result = cryptoClient.Decrypt(EncryptionAlgorithm.RsaOaep256, input);

        return result.Plaintext;
    }

    public byte[] SignHash(string keyIdentifier, byte[] hash)
    {
        _logger.LogInformation("SignHash()");

        var cryptoClient = new CryptographyClient(new Uri(keyIdentifier), _credential);

        var result = cryptoClient.Sign(SignatureAlgorithm.RS256, hash);

        return result.Signature;
    }

    public bool VerifySignature(string keyIdentifier, byte[] hash, byte[] signature)
    {
        _logger.LogInformation("VerifySignature()");

        var cryptoClient = new CryptographyClient(new Uri(keyIdentifier), _credential);

        var result = cryptoClient.Verify(SignatureAlgorithm.RS256, hash, signature);

        return result.IsValid;
    }
}