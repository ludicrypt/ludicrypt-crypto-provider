using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using System;
using System.Collections.Generic;
using Xunit;

namespace Ludicrypt.Pkcs11.Test
{
    internal static class Helpers
    {
        /// <summary>
        /// Serial number of token (smartcard) that should be used by these tests.
        /// First slot with token present is used when both TokenSerial and TokenLabel properties are null.
        /// </summary>
        private static readonly string? _tokenSerial = null;

        /// <summary>
        /// Label of the token (smartcard) that should be used by these tests.
        /// First slot with token present is used when both TokenSerial and TokenLabel properties are null.
        /// </summary>
        private static readonly string? _tokenLabel = null;

        /// <summary>
        /// Finds slot containing the token that matches criteria specified in Settings class
        /// </summary>
        /// <param name='pkcs11Library'>Initialized PKCS11 wrapper</param>
        /// <returns>Slot containing the token that matches criteria</returns>
        public static ISlot GetUsableSlot(IPkcs11Library pkcs11Library)
        {
            // Get list of available slots with token present
            List<ISlot> slots = pkcs11Library.GetSlotList(SlotsType.WithTokenPresent);

            Assert.NotNull(slots);
            Assert.True(slots.Count > 0);

            // First slot with token present is OK...
            ISlot? matchingSlot = slots[0];

            // ...unless there are matching criteria specified in Settings class
            if (_tokenSerial != null || _tokenLabel != null)
            {
                matchingSlot = null;

                foreach (ISlot slot in slots)
                {
                    ITokenInfo? tokenInfo = null;

                    try
                    {
                        tokenInfo = slot.GetTokenInfo();
                    }
                    catch (Pkcs11Exception ex)
                    {
                        if (ex.RV != CKR.CKR_TOKEN_NOT_RECOGNIZED && ex.RV != CKR.CKR_TOKEN_NOT_PRESENT)
                            throw;
                    }

                    if (tokenInfo == null)
                        continue;

                    if (!string.IsNullOrEmpty(_tokenSerial))
                        if (0 != string.Compare(_tokenSerial, tokenInfo.SerialNumber, StringComparison.Ordinal))
                            continue;

                    if (!string.IsNullOrEmpty(_tokenLabel))
                        if (0 != string.Compare(_tokenLabel, tokenInfo.Label, StringComparison.Ordinal))
                            continue;

                    matchingSlot = slot;
                    break;
                }
            }

            Assert.True(matchingSlot != null, "Token matching criteria specified in Settings class is not present");
            return matchingSlot!;
        }
    }
}
