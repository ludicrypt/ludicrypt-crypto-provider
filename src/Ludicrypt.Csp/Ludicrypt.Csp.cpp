#include "pch.h"
#include "Ludicrypt.Csp.h"

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using ludicrypt::CryptoProvider;
using ludicrypt::GetKeyRequest;
using ludicrypt::GetKeyResponse;

///////////////////////////////////////////////////////////////////////////////
//
// Dll entry
//
///////////////////////////////////////////////////////////////////////////////
BOOL WINAPI DllMain(
    HINSTANCE hinstDLL, // handle to DLL module
    DWORD fdwReason,    // reason for calling function
    LPVOID lpReserved)  // reserved
{
    UNREFERENCED_PARAMETER(lpReserved);
    //g_hInstance = (HINSTANCE)hinstDLL;

    // Perform actions based on the reason for calling.
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        // Initialize once for each new process.
        // Return FALSE to fail DLL load.
        //InitializeListHead(&g_SampleKspEnumStateList);
        break;

    case DLL_THREAD_ATTACH:
        // Do thread-specific initialization.
        break;

    case DLL_THREAD_DETACH:
        // Do thread-specific cleanup.
        break;

    case DLL_PROCESS_DETACH:
        // Perform any necessary cleanup.
        //if (g_hRSAProvider)
        //{
        //    BCryptCloseAlgorithmProvider(g_hRSAProvider, 0);
        //}
        break;
    }
    return TRUE;  // Successful DLL_PROCESS_ATTACH.
}

__success(return != FALSE)
extern BOOL WINAPI
CPAcquireContext(
    __out HCRYPTPROV * phProv,
    __in LPCSTR szContainer,
    __in DWORD dwFlags,
    __in PVTableProvStruc pVTable)
{
    /////////////////////////////////////////////////////////////////////////////////////
    // Setup request
    GetKeyRequest request;
    request.set_name("KSPTestRSA");

    // Response
    GetKeyResponse response;

    auto target_str = "unix:///tmp/ludicrypt.sock";

    // Call
    auto channel = grpc::CreateChannel(target_str, grpc::InsecureChannelCredentials());
    std::unique_ptr<CryptoProvider::Stub> stub = CryptoProvider::NewStub(channel);
    ClientContext context;
    Status responseStatus = stub->GetKey(&context, request, &response);
    /////////////////////////////////////////////////////////////////////////////////////

    phProv = NULL;

    SetLastError(E_NOTIMPL);
    return FALSE;
}

__success(return != FALSE)
extern BOOL WINAPI
CPAcquireContextW(
    OUT HCRYPTPROV * phProv,
    IN  LPCWSTR szContainer,
    IN  DWORD dwFlags,
    IN  PVTableProvStrucW pVTable)
{
    SetLastError(E_NOTIMPL);
    return FALSE;
}

__success(return != FALSE)
extern BOOL WINAPI
CPReleaseContext(
    __in  HCRYPTPROV hProv,
    __in  DWORD dwFlags)
{
    SetLastError(E_NOTIMPL);
    return FALSE;
}

__success(return != FALSE)
extern BOOL WINAPI
CPGenKey(
    __in IN  HCRYPTPROV hProv,
    __in IN  ALG_ID Algid,
    __in IN  DWORD dwFlags,
    __out OUT HCRYPTKEY * phKey)
{
    SetLastError(E_NOTIMPL);
    return FALSE;
}

__success(return != FALSE)
extern BOOL WINAPI
CPDeriveKey(
    __in HCRYPTPROV hProv,
    __in ALG_ID Algid,
    __in HCRYPTHASH hHash,
    __in DWORD dwFlags,
    __inout HCRYPTKEY * phKey)
{
    SetLastError(E_NOTIMPL);
    return FALSE;
}

__success(return != FALSE)
extern BOOL WINAPI
CPDestroyKey(
    __in  HCRYPTPROV hProv,
    __in  HCRYPTKEY hKey)
{
    SetLastError(E_NOTIMPL);
    return FALSE;
}

__success(return != FALSE)
extern BOOL WINAPI
CPSetKeyParam(
    __in IN  HCRYPTPROV hProv,
    __in IN  HCRYPTKEY hKey,
    __in IN  DWORD dwParam,
    __in IN  CONST BYTE * pbData,
    __in IN  DWORD dwFlags)
{
    SetLastError(E_NOTIMPL);
    return FALSE;
}

__success(return != FALSE)
extern BOOL WINAPI
CPGetKeyParam(
    __in IN  HCRYPTPROV hProv,
    __in IN  HCRYPTKEY hKey,
    __in IN  DWORD dwParam,
    __out_bcount_part_opt(*pcbDataLen, *pcbDataLen) OUT LPBYTE pbData,
    __inout IN OUT LPDWORD pcbDataLen,
    __in IN  DWORD dwFlags)
{
    SetLastError(E_NOTIMPL);
    return FALSE;
}

__success(return != FALSE)
extern BOOL WINAPI
CPSetProvParam(
    __in HCRYPTPROV hProv,
    __in DWORD dwParam,
    _When_(dwFlags == PP_KEYSET_SEC_DESCR, _At_((PSECURITY_DESCRIPTOR)pbData, __in))
    _When_(dwFlags == PP_UI_PROMPT, _At_((LPWSTR)pbData, __in))
    _When_(dwFlags == PP_DELETEKEY, _At_((DWORD*)pbData, __in))
    __in CONST BYTE * pbData,
    __in DWORD dwFlags)
{
    SetLastError(E_NOTIMPL);
    return FALSE;
}

__success(return != FALSE)
extern BOOL WINAPI
CPGetProvParam(
    __in IN  HCRYPTPROV hProv,
    __in IN  DWORD dwParam,
    __out_bcount_part_opt(*pcbDataLen, *pcbDataLen) OUT LPBYTE pbData,
    __inout IN OUT LPDWORD pcbDataLen,
    __in IN  DWORD dwFlags)
{
    SetLastError(E_NOTIMPL);
    return FALSE;
}

__success(return != FALSE)
extern BOOL WINAPI
CPSetHashParam(
    __in HCRYPTPROV hProv,
    __in HCRYPTHASH hHash,
    __in DWORD dwParam,
    __in CONST BYTE * pbData,
    __in DWORD dwFlags)
{
    SetLastError(E_NOTIMPL);
    return FALSE;
}

__success(return != FALSE)
extern BOOL WINAPI
CPGetHashParam(
    __in                                            HCRYPTPROV hProv,
    __in                                            HCRYPTHASH hHash,
    __in                                            DWORD dwParam,
    __out_bcount_part_opt(*pwDataLen, *pwDataLen)   LPBYTE pbData,
    __inout /* __deref_out_range(16, MAX_HASH_SIZE) */   DWORD * pwDataLen,
    __in                                            DWORD dwFlags)
{
    SetLastError(E_NOTIMPL);
    return FALSE;
}

__success(return != FALSE)
extern BOOL WINAPI
CPExportKey(
    __in IN  HCRYPTPROV hProv,
    __in IN  HCRYPTKEY hKey,
    __in IN  HCRYPTKEY hPubKey,
    __in IN  DWORD dwBlobType,
    __in IN  DWORD dwFlags,
    __out_bcount_part_opt(*pcbDataLen, *pcbDataLen) OUT LPBYTE pbData,
    __inout IN OUT LPDWORD pcbDataLen)
{
    SetLastError(E_NOTIMPL);
    return FALSE;
}

__success(return != FALSE)
extern BOOL WINAPI
CPImportKey(
    __in IN  HCRYPTPROV hProv,
    __in_bcount(cbDataLen) IN  CONST BYTE * pbData,
    __in IN  DWORD cbDataLen,
    __in IN  HCRYPTKEY hPubKey,
    __in IN  DWORD dwFlags,
    __out OUT HCRYPTKEY * phKey)
{
    SetLastError(E_NOTIMPL);
    return FALSE;
}

__success(return != FALSE)
extern BOOL WINAPI
CPEncrypt(
    __in HCRYPTPROV hProv,
    __in HCRYPTKEY hKey,
    __in HCRYPTHASH hHash,
    __in BOOL fFinal,
    __in DWORD dwFlags,
    __inout_bcount_part_opt(cbBufLen, *pcbDataLen) IN OUT LPBYTE pbData,
    __inout LPDWORD pcbDataLen,
    __in DWORD cbBufLen)
{
    SetLastError(E_NOTIMPL);
    return FALSE;
}

__success(return != FALSE)
extern BOOL WINAPI
CPDecrypt(
    __in IN  HCRYPTPROV hProv,
    __in IN  HCRYPTKEY hKey,
    __in IN  HCRYPTHASH hHash,
    __in IN  BOOL fFinal,
    __in IN  DWORD dwFlags,
    __inout_bcount_part_opt(*pcbDataLen, *pcbDataLen) IN OUT LPBYTE pbData,
    __inout IN OUT LPDWORD pcbDataLen)
{
    SetLastError(E_NOTIMPL);
    return FALSE;
}

__success(return != FALSE)
extern BOOL WINAPI
CPCreateHash(
    __in IN  HCRYPTPROV hProv,
    __in IN  ALG_ID Algid,
    __in IN  HCRYPTKEY hKey,
    __in IN  DWORD dwFlags,
    __out OUT HCRYPTHASH * phHash)
{
    SetLastError(E_NOTIMPL);
    return FALSE;
}

__success(return != FALSE)
extern BOOL WINAPI
CPHashData(
    __in IN  HCRYPTPROV hProv,
    __in IN  HCRYPTHASH hHash,
    __in_bcount(cbDataLen) IN  CONST BYTE * pbData,
    __in IN  DWORD cbDataLen,
    __in IN  DWORD dwFlags)
{
    SetLastError(E_NOTIMPL);
    return FALSE;
}

__success(return != FALSE)
extern BOOL WINAPI
CPHashSessionKey(
    __in  HCRYPTPROV hProv,
    __in  HCRYPTHASH hHash,
    __in  HCRYPTKEY hKey,
    __in  DWORD dwFlags)
{
    SetLastError(E_NOTIMPL);
    return FALSE;
}

__success(return != FALSE)
extern BOOL WINAPI
CPSignHash(
    __in IN  HCRYPTPROV hProv,
    __in IN  HCRYPTHASH hHash,
    __in IN  DWORD dwKeySpec,
    __in IN  LPCWSTR szDescription,
    __in IN  DWORD dwFlags,
    __out_bcount_part_opt(*pcbSigLen, *pcbSigLen) OUT LPBYTE pbSignature,
    __inout IN OUT LPDWORD pcbSigLen)
{
    SetLastError(E_NOTIMPL);
    return FALSE;
}

__success(return != FALSE)
extern BOOL WINAPI
CPDestroyHash(
    __in  HCRYPTPROV hProv,
    __in  HCRYPTHASH hHash)
{
    SetLastError(E_NOTIMPL);
    return FALSE;
}

__success(return != FALSE)
extern BOOL WINAPI
CPVerifySignature(
    __in IN  HCRYPTPROV hProv,
    __in IN  HCRYPTHASH hHash,
    __in_bcount(cbSigLen) IN  CONST BYTE * pbSignature,
    __in IN  DWORD cbSigLen,
    __in IN  HCRYPTKEY hPubKey,
    __in IN  LPCWSTR szDescription,
    __in IN  DWORD dwFlags)
{
    SetLastError(E_NOTIMPL);
    return FALSE;
}

__success(return != FALSE)
extern BOOL WINAPI
CPGenRandom(
    __in IN  HCRYPTPROV hProv,
    __in IN  DWORD cbLen,
    __out_bcount_full(cbLen) OUT LPBYTE pbBuffer)
{
    SetLastError(E_NOTIMPL);
    return FALSE;
}

__success(return != FALSE)
extern BOOL WINAPI
CPGetUserKey(
    __in IN  HCRYPTPROV hProv,
    __in IN  DWORD dwKeySpec,
    __out OUT HCRYPTKEY * phUserKey)
{
    SetLastError(E_NOTIMPL);
    return FALSE;
}

__success(return != FALSE)
extern BOOL WINAPI
CPDuplicateHash(
    __in IN  HCRYPTPROV hProv,
    __in IN  HCRYPTHASH hHash,
    __reserved IN  LPDWORD pdwReserved,
    __in IN  DWORD dwFlags,
    __out OUT HCRYPTHASH * phHash)
{
    SetLastError(E_NOTIMPL);
    return FALSE;
}

__success(return != FALSE)
extern BOOL WINAPI
CPDuplicateKey(
    __in IN  HCRYPTPROV hProv,
    __in IN  HCRYPTKEY hKey,
    __reserved IN  LPDWORD pdwReserved,
    __in IN  DWORD dwFlags,
    __out OUT HCRYPTKEY * phKey)
{
    SetLastError(E_NOTIMPL);
    return FALSE;
}
