#include "pch.h"

#define LUDICRYPT_KEY_STORAGE_PROVIDER L"Ludicrypt Key Storage Provider"
#define TEST_KEY_NAME L"TestRSA" //"L"TestEC"

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)


static const  BYTE rgbMsg[] =
{
    0x04, 0x87, 0xec, 0x66, 0xa8, 0xbf, 0x17, 0xa6,
    0xe3, 0x62, 0x6f, 0x1a, 0x55, 0xe2, 0xaf, 0x5e,
    0xbc, 0x54, 0xa4, 0xdc, 0x68, 0x19, 0x3e, 0x94,
};

static const BYTE rgbPlaintext[] =
{
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

TEST(Integration, SignAndVerify) {
    NCRYPT_PROV_HANDLE      hProv = NULL;
    NCRYPT_KEY_HANDLE       hKey = NULL;
    BCRYPT_KEY_HANDLE       hTmpKey = NULL;
    SECURITY_STATUS         secStatus = ERROR_SUCCESS;
    BCRYPT_ALG_HANDLE       hHashAlg = NULL,
                            hSignAlg = NULL;
    BCRYPT_HASH_HANDLE      hHash = NULL;
    NTSTATUS                status = STATUS_UNSUCCESSFUL;
    DWORD                   cbData = 0,
                            cbHash = 0,
                            cbBlob = 0,
                            cbSignature = 0,
                            cbHashObject = 0;
    PBYTE                   pbHashObject = NULL;
    PBYTE                   pbHash = NULL,
                            pbBlob = NULL,
                            pbSignature = NULL;
    BCRYPT_PKCS1_PADDING_INFO   PKCS1PaddingInfo = { 0 };

    //open an algorithm handle
    if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(
        &hHashAlg,
        BCRYPT_SHA256_ALGORITHM,
        NULL,
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
        goto Cleanup;
    }

    if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(
        &hSignAlg,
        BCRYPT_RSA_ALGORITHM,
        NULL,
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
        goto Cleanup;
    }

    //calculate the size of the buffer to hold the hash object
    if (!NT_SUCCESS(status = BCryptGetProperty(
        hHashAlg,
        BCRYPT_OBJECT_LENGTH,
        (PBYTE)&cbHashObject,
        sizeof(DWORD),
        &cbData,
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
        goto Cleanup;
    }

    //allocate the hash object on the heap
    pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
    if (NULL == pbHashObject)
    {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    //calculate the length of the hash
    if (!NT_SUCCESS(status = BCryptGetProperty(
        hHashAlg,
        BCRYPT_HASH_LENGTH,
        (PBYTE)&cbHash,
        sizeof(DWORD),
        &cbData,
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
        goto Cleanup;
    }

    //allocate the hash buffer on the heap
    pbHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHash);
    if (NULL == pbHash)
    {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    //create a hash
    if (!NT_SUCCESS(status = BCryptCreateHash(
        hHashAlg,
        &hHash,
        pbHashObject,
        cbHashObject,
        NULL,
        0,
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptCreateHash\n", status);
        goto Cleanup;
    }


    //hash some data
    if (!NT_SUCCESS(status = BCryptHashData(
        hHash,
        (PBYTE)rgbMsg,
        sizeof(rgbMsg),
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptHashData\n", status);
        goto Cleanup;
    }

    //close the hash
    if (!NT_SUCCESS(status = BCryptFinishHash(
        hHash,
        pbHash,
        cbHash,
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptFinishHash\n", status);
        goto Cleanup;
    }

    //open handle to KSP
    if (FAILED(secStatus = NCryptOpenStorageProvider(
        &hProv,
        LUDICRYPT_KEY_STORAGE_PROVIDER,
        0)))
    {
        wprintf(L"**** Error 0x%x returned by NCryptOpenStorageProvider\n", secStatus);
        goto Cleanup;
    }

    //open an existing key
    if (FAILED(secStatus = NCryptOpenKey(
        hProv,
        &hKey,
        TEST_KEY_NAME,
        0,
        0)))
    {
        wprintf(L"**** Error 0x%x returned by NCryptCreatePersistedKey\n", secStatus);
        goto Cleanup;
    }

    PKCS1PaddingInfo.pszAlgId = NCRYPT_SHA256_ALGORITHM;

    //sign the hash
    if (FAILED(secStatus = NCryptSignHash(
        hKey,
        &PKCS1PaddingInfo,
        pbHash,
        cbHash,
        NULL,
        0,
        &cbSignature,
        NCRYPT_PAD_PKCS1_FLAG)))
    {
        wprintf(L"**** Error 0x%x returned by NCryptSignHash\n", secStatus);
        goto Cleanup;
    }


    //allocate the signature buffer
    pbSignature = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbSignature);
    if (NULL == pbSignature)
    {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    if (FAILED(secStatus = NCryptSignHash(
        hKey,
        &PKCS1PaddingInfo,
        pbHash,
        cbHash,
        pbSignature,
        cbSignature,
        &cbSignature,
        NCRYPT_PAD_PKCS1_FLAG)))
    {
        wprintf(L"**** Error 0x%x returned by NCryptSignHash\n", secStatus);
        goto Cleanup;
    }

    if (FAILED(secStatus = NCryptExportKey(
        hKey,
        NULL,
        BCRYPT_RSAPUBLIC_BLOB,
        NULL,
        NULL,
        0,
        &cbBlob,
        0)))
    {
        wprintf(L"**** Error 0x%x returned by NCryptExportKey\n", secStatus);
        goto Cleanup;
    }

    pbBlob = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbBlob);
    if (NULL == pbBlob)
    {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    if (FAILED(secStatus = NCryptExportKey(
        hKey,
        NULL,
        BCRYPT_RSAPUBLIC_BLOB,
        NULL,
        pbBlob,
        cbBlob,
        &cbBlob,
        0)))
    {
        wprintf(L"**** Error 0x%x returned by NCryptExportKey\n", secStatus);
        goto Cleanup;
    }

    if (!NT_SUCCESS(status = BCryptImportKeyPair(
        hSignAlg,
        NULL,
        BCRYPT_RSAPUBLIC_BLOB,
        &hTmpKey,
        pbBlob,
        cbBlob,
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptImportKeyPair\n", status);
        goto Cleanup;
    }

    if (!NT_SUCCESS(status = BCryptVerifySignature(
        hTmpKey,
        &PKCS1PaddingInfo,
        pbHash,
        cbHash,
        pbSignature,
        cbSignature,
        NCRYPT_PAD_PKCS1_FLAG)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptVerifySignature\n", status);
        goto Cleanup;
    }

    wprintf(L"Success!\n");

Cleanup:

    if (hHashAlg)
    {
        BCryptCloseAlgorithmProvider(hHashAlg, 0);
    }

    if (hSignAlg)
    {
        BCryptCloseAlgorithmProvider(hSignAlg, 0);
    }

    if (hHash)
    {
        BCryptDestroyHash(hHash);
    }

    if (pbHashObject)
    {
        HeapFree(GetProcessHeap(), 0, pbHashObject);
    }

    if (pbHash)
    {
        HeapFree(GetProcessHeap(), 0, pbHash);
    }

    if (pbSignature)
    {
        HeapFree(GetProcessHeap(), 0, pbSignature);
    }

    if (pbBlob)
    {
        HeapFree(GetProcessHeap(), 0, pbBlob);
    }

    if (hTmpKey)
    {
        BCryptDestroyKey(hTmpKey);
    }

    if (hKey)
    {
        //NCryptDeleteKey(hKey, 0);
        NCryptFreeObject(hKey);
    }

    if (hProv)
    {
        NCryptFreeObject(hProv);
    }

    //EXPECT_EQ(1, 1);
    EXPECT_FALSE(FAILED(secStatus));
    EXPECT_TRUE(NT_SUCCESS(status));
}

TEST(Integration, EncryptAndDecrypt) {
    NCRYPT_PROV_HANDLE      hProv = NULL;
    NCRYPT_KEY_HANDLE       hKey = NULL;
    BCRYPT_KEY_HANDLE       hTmpKey = NULL;
    SECURITY_STATUS         secStatus = ERROR_SUCCESS;
    NTSTATUS                status = STATUS_UNSUCCESSFUL;
    BCRYPT_ALG_HANDLE       hRsaAlg = NULL;
    DWORD                   cbPublicKeyBlob = 0,
                            cbPlainText = 0,
                            cbCipherText = 0;
    PBYTE                   pbPublicKeyBlob = NULL,
                            pbPlainText = NULL,
                            pbCipherText = NULL;
    BCRYPT_OAEP_PADDING_INFO    OAEPPaddingInfo = { 0 };

    //open handle to KSP
    if (FAILED(secStatus = NCryptOpenStorageProvider(
        &hProv,
        LUDICRYPT_KEY_STORAGE_PROVIDER,
        0)))
    {
        wprintf(L"**** Error 0x%x returned by NCryptOpenStorageProvider\n", secStatus);
        goto Cleanup;
    }

    //open an existing key
    if (FAILED(secStatus = NCryptOpenKey(
        hProv,
        &hKey,
        TEST_KEY_NAME,
        0,
        0)))
    {
        wprintf(L"**** Error 0x%x returned by NCryptCreatePersistedKey\n", secStatus);
        goto Cleanup;
    }

    if (FAILED(secStatus = NCryptExportKey(
        hKey,
        NULL,
        BCRYPT_RSAPUBLIC_BLOB,
        NULL,
        NULL,
        0,
        &cbPublicKeyBlob,
        0)))
    {
        wprintf(L"**** Error 0x%x returned by NCryptExportKey\n", secStatus);
        goto Cleanup;
    }

    pbPublicKeyBlob = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPublicKeyBlob);
    if (NULL == pbPublicKeyBlob)
    {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    if (FAILED(secStatus = NCryptExportKey(
        hKey,
        NULL,
        BCRYPT_RSAPUBLIC_BLOB,
        NULL,
        pbPublicKeyBlob,
        cbPublicKeyBlob,
        &cbPublicKeyBlob,
        0)))
    {
        wprintf(L"**** Error 0x%x returned by NCryptExportKey\n", secStatus);
        goto Cleanup;
    }

    if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(
        &hRsaAlg,
        BCRYPT_RSA_ALGORITHM,
        NULL,
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
        goto Cleanup;
    }

    if (!NT_SUCCESS(status = BCryptImportKeyPair(
        hRsaAlg,
        NULL,
        BCRYPT_RSAPUBLIC_BLOB,
        &hTmpKey,
        pbPublicKeyBlob,
        cbPublicKeyBlob,
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptImportKeyPair\n", status);
        goto Cleanup;
    }

    OAEPPaddingInfo.pszAlgId = NCRYPT_SHA256_ALGORITHM;
    OAEPPaddingInfo.pbLabel = NULL;
    OAEPPaddingInfo.cbLabel = 0;

    //encrypt the data
    if (!NT_SUCCESS(status = BCryptEncrypt(
        hTmpKey,
        (PBYTE)rgbPlaintext,
        sizeof(rgbPlaintext),
        &OAEPPaddingInfo,
        NULL,
        0,
        NULL,
        0,
        &cbCipherText,
        BCRYPT_PAD_OAEP)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptEncrypt\n", status);
        goto Cleanup;
    }

    //allocate the ciphertext buffer
    pbCipherText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbCipherText);
    if (NULL == pbCipherText)
    {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    if (!NT_SUCCESS(status = BCryptEncrypt(
        hTmpKey,
        (PBYTE)rgbPlaintext,
        sizeof(rgbPlaintext),
        &OAEPPaddingInfo,
        NULL,
        0,
        pbCipherText,
        cbCipherText,
        &cbCipherText,
        BCRYPT_PAD_OAEP)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptEncrypt\n", status);
        goto Cleanup;
    }

    //decrypt data
    /*if (FAILED(secStatus = NCryptDecrypt(
        hKey,
        pbCipherText,
        cbCipherText,
        &OAEPPaddingInfo,
        NULL,
        0,
        &cbPlainText,
        NCRYPT_PAD_OAEP_FLAG)))
    {
        wprintf(L"**** Error 0x%x returned by NCryptSignHash\n", secStatus);
        goto Cleanup;
    }*/

    cbPlainText = cbCipherText;

    //allocate the plain text buffer
    pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText);
    if (NULL == pbPlainText)
    {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    if (FAILED(secStatus = NCryptDecrypt(
        hKey,
        pbCipherText,
        cbCipherText,
        &OAEPPaddingInfo,
        pbPlainText,
        cbPlainText,
        &cbPlainText,
        NCRYPT_PAD_OAEP_FLAG)))
    {
        wprintf(L"**** Error 0x%x returned by NCryptSignHash\n", secStatus);
        goto Cleanup;
    }

    if (0 != memcmp(pbPlainText, (PBYTE)rgbPlaintext, sizeof(rgbPlaintext)))
    {
        wprintf(L"Expected decrypted text comparison failed.\n");
        goto Cleanup;
    }

    wprintf(L"Success!\n");

Cleanup:

    if (hRsaAlg)
    {
        BCryptCloseAlgorithmProvider(hRsaAlg, 0);
    }

    if (pbPlainText)
    {
        HeapFree(GetProcessHeap(), 0, pbPlainText);
    }

    if (pbCipherText)
    {
        HeapFree(GetProcessHeap(), 0, pbCipherText);
    }

    if (pbPublicKeyBlob)
    {
        HeapFree(GetProcessHeap(), 0, pbPublicKeyBlob);
    }

    if (hTmpKey)
    {
        BCryptDestroyKey(hTmpKey);
    }

    if (hKey)
    {
        //NCryptDeleteKey(hKey, 0);
        NCryptFreeObject(hKey);
    }

    if (hProv)
    {
        NCryptFreeObject(hProv);
    }

    EXPECT_FALSE(FAILED(secStatus));
    EXPECT_TRUE(NT_SUCCESS(status));
}
