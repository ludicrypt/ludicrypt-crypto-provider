using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Xunit;

namespace Ludicrypt.Pkcs11.Test
{
    public class Integration
    {
        private static readonly Pkcs11InteropFactories _factories = new Pkcs11InteropFactories();
        private static readonly string _pkcs11LibraryPath = @"..\..\build\src\ludicrypt-pkcs11\Debug\ludicrypt-pkcs11.dll";
        private static readonly AppType _appType = AppType.MultiThreaded;
        private static readonly string _normalUserPin = @"11111111";

        [Fact]
        public void SignAndVerify()
        {
            using var pkcs11Library = _factories.Pkcs11LibraryFactory.LoadPkcs11Library(_factories, _pkcs11LibraryPath, _appType);

            // Find first slot with token present
            ISlot slot = Helpers.GetUsableSlot(pkcs11Library);

            // Open RW session
            using (ISession session = slot.OpenSession(SessionType.ReadWrite))
            {
                // Login as normal user
                session.Login(CKU.CKU_USER, _normalUserPin);

                // Generate key pair
                IObjectHandle? publicKey = null;
                IObjectHandle? privateKey = null;

                // TODO: Find and load an existing key
                //Helpers.GenerateKeyPair(session, out publicKey, out privateKey);

                // Specify signing mechanism
                IMechanism mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_SHA1_RSA_PKCS);

                byte[] sourceData = ConvertUtils.Utf8StringToBytes("Hello world");

                // Sign data
                byte[] signature = session.Sign(mechanism, privateKey, sourceData);

                // Do something interesting with signature

                // Verify signature
                bool isValid = false;
                session.Verify(mechanism, publicKey, sourceData, signature, out isValid);

                // Do something interesting with verification result
                Assert.True(isValid);

                session.DestroyObject(privateKey);
                session.DestroyObject(publicKey);
                session.Logout();
            }
        }
    }
}
