using Google.Protobuf;
using Grpc.Core;
using Ludicrypt.Backend.Interface;

namespace Ludicrypt.Services;

public class CryptoProviderService : CryptoProvider.CryptoProviderBase
{
    private readonly ILogger<CryptoProviderService> _logger;
    private readonly ICryptoProvider _provider;

    public CryptoProviderService(
        ILogger<CryptoProviderService> logger,
        ICryptoProvider provider)
    {
        _logger = logger;
        _provider = provider;
    }

    //public override Task<KspOpenStorageProviderResponse> OpenStorageProvider(KspOpenStorageProviderRequest request, ServerCallContext context)
    //{
    //    _provider.Initialize();

    //    return Task.FromResult(new KspOpenStorageProviderResponse
    //    {
    //    });
    //}

    public override Task<GetKeyResponse> GetKey(GetKeyRequest request, ServerCallContext context)
    {
        var key = _provider.GetKey(request.Name);

        return Task.FromResult(new GetKeyResponse
        {
            Name = key.Name,
            Algorithm = key.Algorithm,
            Identifier = key.Identifier,
            PublicExponent = ByteString.CopyFrom(key.PublicExponent),
            Modulus = ByteString.CopyFrom(key.Modulus)
        }); ;
    }

    public override Task<CreateKeyResponse> CreateKey(CreateKeyRequest request, ServerCallContext context)
    {
        var key = _provider.CreateKey(request.Name, request.Algorithm);

        return Task.FromResult(new CreateKeyResponse
        {
            Name = key.Name,
            Algorithm = key.Algorithm,
            Identifier = key.Identifier
        });
    }

    //public override Task<KspGetProviderPropertyResponse> GetProviderProperty(KspGetProviderPropertyRequest request, ServerCallContext context)
    //{
    //    // TODO: Validate request.ProviderHandle

    //    var propertyValue = NCryptGetProperty(
    //        new SafeProviderHandle((IntPtr)request.ProviderHandle, ownsHandle: false),
    //        request.PropertyName,
    //        (NCryptGetPropertyFlags)request.Flags);

    //    return Task.FromResult(new KspGetProviderPropertyResponse
    //    {
    //        PropertyValue = ByteString.CopyFrom(propertyValue)
    //    });
    //}

    //public override Task<KspGetKeyPropertyResponse> GetKeyProperty(KspGetKeyPropertyRequest request, ServerCallContext context)
    //{
    //    // TODO: Validate request.ProviderHandle

    //    var propertyValue = NCryptGetProperty(
    //        new SafeKeyHandle((IntPtr)request.KeyHandle, ownsHandle: false),
    //        request.PropertyName,
    //        (NCryptGetPropertyFlags)request.Flags);

    //    return Task.FromResult(new KspGetKeyPropertyResponse
    //    {
    //        PropertyValue = ByteString.CopyFrom(propertyValue)
    //    });
    //}

    //public override Task<KspSetProviderPropertyResponse> SetProviderProperty(KspSetProviderPropertyRequest request, ServerCallContext context)
    //{
    //    // TODO: Validate request.ProviderHandle

    //    NCryptSetProperty(
    //        new SafeProviderHandle((IntPtr)request.ProviderHandle, ownsHandle: false),
    //        request.PropertyName,
    //        request.PropertyValue.ToByteArray(),
    //        (NCryptSetPropertyFlags)request.Flags);

    //    return Task.FromResult(new KspSetProviderPropertyResponse
    //    {
    //    });
    //}

    //public override Task<KspSetKeyPropertyResponse> SetKeyProperty(KspSetKeyPropertyRequest request, ServerCallContext context)
    //{
    //    // TODO: Validate request.ProviderHandle

    //    NCryptSetProperty(
    //        new SafeKeyHandle((IntPtr)request.KeyHandle, ownsHandle: false),
    //        request.PropertyName,
    //        request.PropertyValue.ToByteArray(),
    //        (NCryptSetPropertyFlags)request.Flags);

    //    return Task.FromResult(new KspSetKeyPropertyResponse
    //    {
    //    });
    //}

    //public override Task<KspFinalizeKeyResponse> FinalizeKey(KspFinalizeKeyRequest request, ServerCallContext context)
    //{
    //    // TODO: Validate request.ProviderHandle

    //    NCryptFinalizeKey(
    //        new SafeKeyHandle((IntPtr)request.KeyHandle, ownsHandle: false),
    //        (NCryptFinalizeKeyFlags)request.Flags).ThrowOnError();

    //    return Task.FromResult(new KspFinalizeKeyResponse
    //    {
    //    });
    //}

    public override Task<DeleteKeyResponse> DeleteKey(DeleteKeyRequest request, ServerCallContext context)
    {
        _provider.DeleteKey(request.Identifier);

        return Task.FromResult(new DeleteKeyResponse
        {
        });
    }

    //public override Task<KspFreeProviderResponse> FreeProvider(KspFreeProviderRequest request, ServerCallContext context)
    //{
    //    // TODO: Validate request.ProviderHandle

    //    var pinnedProviderHandle = GCHandle.FromIntPtr((IntPtr)request.ProviderHandle);

    //    ((SafeProviderHandle)pinnedProviderHandle.Target!).Close();
    //    pinnedProviderHandle.Free();

    //    return Task.FromResult(new KspFreeProviderResponse
    //    {
    //    });
    //}

    //public override Task<KspFreeKeyResponse> FreeKey(KspFreeKeyRequest request, ServerCallContext context)
    //{
    //    // TODO: Validate request.ProviderHandle

    //    var pinnedKeyHandle = GCHandle.FromIntPtr((IntPtr)request.KeyHandle);

    //    ((SafeKeyHandle)pinnedKeyHandle.Target!).Close();
    //    pinnedKeyHandle.Free();

    //    return Task.FromResult(new KspFreeKeyResponse
    //    {
    //    });
    //}

    //public override Task<KspFreeBufferResponse> FreeBuffer(KspFreeBufferRequest request, ServerCallContext context)
    //{
    //    var pinnedBufferHandle = GCHandle.FromIntPtr((IntPtr)request.BufferHandle);

    //    ((SafeBufferHandle)pinnedBufferHandle.Target!).Close();
    //    pinnedBufferHandle.Free();

    //    return Task.FromResult(new KspFreeBufferResponse
    //    {
    //    });
    //}

    public override Task<EncryptResponse> Encrypt(EncryptRequest request, ServerCallContext context)
    {
        var outut = _provider.Encrypt(request.Identifier, request.Input.ToByteArray());

        return Task.FromResult(new EncryptResponse
        {
            Output = ByteString.CopyFrom(outut)
        });
    }

    public override Task<DecryptResponse> Decrypt(DecryptRequest request, ServerCallContext context)
    {
        var outut = _provider.Decrypt(request.Identifier, request.Input.ToByteArray());

        return Task.FromResult(new DecryptResponse
        {
            Output = ByteString.CopyFrom(outut)
        });
    }

    //public override Task<KspIsAlgSupportedResponse> IsAlgSupported(KspIsAlgSupportedRequest request, ServerCallContext context)
    //{
    //    // TODO: Validate request.ProviderHandle

    //    NCryptIsAlgSupported(
    //        new SafeProviderHandle((IntPtr)request.ProviderHandle, ownsHandle: false),
    //        request.Algorithm,
    //        (NCryptIsAlgSupportedFlags)request.Flags).ThrowOnError();

    //    return Task.FromResult(new KspIsAlgSupportedResponse
    //    {
    //    });
    //}

    //public unsafe override Task<KspEnumAlgorithmsResponse> EnumAlgorithms(KspEnumAlgorithmsRequest request, ServerCallContext context)
    //{
    //    // TODO: Validate request.ProviderHandle

    //    NCryptEnumAlgorithms(
    //        new SafeProviderHandle((IntPtr)request.ProviderHandle, ownsHandle: false),
    //        (AlgorithmOperations)request.AlgorithmClass,
    //        out int algCount,
    //        out NCryptAlgorithmName* algList,
    //        (NCryptEnumAlgorithmsFlags)request.Flags).ThrowOnError();

    //    var algListSpan = new ReadOnlySpan<byte>(algList, algCount * Marshal.SizeOf<NCryptAlgorithmName>());
    //    var algListByteString = ByteString.CopyFrom(algListSpan);

    //    NCryptFreeBuffer(algList).ThrowOnError();

    //    return Task.FromResult(new KspEnumAlgorithmsResponse
    //    {
    //        Algorithms = algListByteString
    //    });
    //}

    //public unsafe override Task<KspEnumKeysResponse> EnumKeys(KspEnumKeysRequest request, ServerCallContext context)
    //{
    //    // TODO: Validate request.ProviderHandle

    //    // TODO: Refactor all this... it's broken and unsafe

    //    void* enumState = (void*)request.EnumStateHandle;

    //    NCryptEnumKeys(
    //        new SafeProviderHandle((IntPtr)request.ProviderHandle, ownsHandle: false),
    //        request.Scope,
    //        out NCryptKeyName* keyName,
    //        ref enumState,
    //        (NCryptEnumKeysFlags)request.Flags
    //        ).ThrowOnError();

    //    var keyNameSpan = new ReadOnlySpan<byte>(keyName, Marshal.SizeOf<NCryptKeyName>());
    //    var keyNameByteString = ByteString.CopyFrom(keyNameSpan);

    //    return Task.FromResult(new KspEnumKeysResponse
    //    {
    //        KeyName = keyNameByteString,
    //        EnumStateHandle = (long)enumState
    //    });
    //}

    //public override Task<KspImportKeyResponse> ImportKey(KspImportKeyRequest request, ServerCallContext context)
    //{
    //    // TODO: Validate request.ProviderHandle

    //    //var keyHandle = new SafeKeyHandle((IntPtr)request.KeyHandle, ownsHandle: false);

    //    //NCryptImportKey();

    //    return Task.FromResult(new KspImportKeyResponse
    //    {
    //    });
    //}

    //public override Task<KspExportKeyResponse> ExportKey(KspExportKeyRequest request, ServerCallContext context)
    //{
    //    return Task.FromResult(new KspExportKeyResponse
    //    {
    //    });
    //}

    public override Task<SignHashResponse> SignHash(SignHashRequest request, ServerCallContext context)
    {
        var signature = _provider.SignHash(request.Identifier, request.Hash.ToByteArray());

        return Task.FromResult(new SignHashResponse
        {
            Signature = ByteString.CopyFrom(signature)
        });
    }

    public override Task<VerifySignatureResponse> VerifySignature(VerifySignatureRequest request, ServerCallContext context)
    {
        var isVerified = _provider.VerifySignature(request.Identifier, request.Hash.ToByteArray(), request.Signature.ToByteArray());

        return Task.FromResult(new VerifySignatureResponse
        {
        });
    }

    //public override Task<KspResponse> PromptUser(KspRequest request, ServerCallContext context)
    //{
    //    return Task.FromResult(new KspResponse
    //    {
    //        Message = "Not implemented"
    //    });
    //}

    //public override Task<KspResponse> NotifyChangeKey(KspRequest request, ServerCallContext context)
    //{
    //    return Task.FromResult(new KspResponse
    //    {
    //        Message = "Not implemented"
    //    });
    //}

    //public override Task<KspResponse> SecretAgreement(KspRequest request, ServerCallContext context)
    //{
    //    return Task.FromResult(new KspResponse
    //    {
    //        Message = "Not implemented"
    //    });
    //}

    //public override Task<KspResponse> DeriveKey(KspRequest request, ServerCallContext context)
    //{
    //    return Task.FromResult(new KspResponse
    //    {
    //        Message = "Not implemented"
    //    });
    //}

    //public override Task<KspResponse> FreeSecret(KspRequest request, ServerCallContext context)
    //{
    //    return Task.FromResult(new KspResponse
    //    {
    //        Message = "Not implemented"
    //    });
    //}

    //public override Task<KspResponse> KeyDerivation(KspRequest request, ServerCallContext context)
    //{
    //    return Task.FromResult(new KspResponse
    //    {
    //        Message = "Not implemented"
    //    });
    //}

    //public override Task<KspResponse> CreateClaim(KspRequest request, ServerCallContext context)
    //{
    //    return Task.FromResult(new KspResponse
    //    {
    //        Message = "Not implemented"
    //    });
    //}

    //public override Task<KspResponse> VerifyClaim(KspRequest request, ServerCallContext context)
    //{
    //    return Task.FromResult(new KspResponse
    //    {
    //        Message = "Not implemented"
    //    });
    //}
}
