// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
namespace Microsoft.InformationProtection.Web.Models
{
    using System;
    using System.Security.Cryptography;
    using Microsoft.InformationProtection.Web.Models.Extensions;
    using sg = System.Globalization;
    public class KSPKey : IKey
    {
        private string kspName;
        private string keyId;
        private PublicKey storedPublicKey = null;

        public KSPKey(string id, string keyStorageProviderName)
        {
            keyId = id;
            kspName = keyStorageProviderName;
        }

        public PublicKey GetPublicKey()
        {
            if(storedPublicKey != null)
            {
                return storedPublicKey;
            }

            CngProvider provider = new CngProvider(kspName);
            CngKey key;

            // If you get an error here, make sure you register the KSP and the project run in 64bits
            if(!CngKey.Exists(keyId, provider))
            {
                throw new System.ArgumentException("Key " + keyId + " not found " + kspName);
            }

            key = CngKey.Open(keyId, provider);
            RSACng cryptoEngine = new RSACng(key);

            var rsaKeyInfo = cryptoEngine.ExportParameters(false);
            var exponent = ByteArrayToUInt(rsaKeyInfo.Exponent);
            var modulus = Convert.ToBase64String(rsaKeyInfo.Modulus);
            storedPublicKey = new PublicKey(modulus, exponent);
            cryptoEngine.Dispose();
            key.Dispose();

            return storedPublicKey;
        }

        public byte[] Decrypt(byte[] encryptedData)
        {
            CngProvider provider = new CngProvider(kspName);
            CngKey key;

            // If you get an error here, make sure you register the KSP and the project run in 64bits
            if(!CngKey.Exists(keyId, provider))
            {
                throw new System.ArgumentException("Key " + keyId + " not found in " + kspName);
            }

            key = CngKey.Open(keyId, provider);
            RSACng cryptoEngine = new RSACng(key);

            var decryptedData = cryptoEngine.Decrypt(encryptedData, System.Security.Cryptography.RSAEncryptionPadding.OaepSHA256);

            cryptoEngine.Dispose();
            key.Dispose();

            return decryptedData;
        }

        private static uint ByteArrayToUInt(byte[] array)
        {
            uint retVal = 0;

            checked
            {
              if (BitConverter.IsLittleEndian)
              {
                  for (int index = array.Length - 1; index >= 0; index--)
                  {
                      retVal = (retVal << 8) + array[index];
                  }
              }
              else
              {
                  for (int index = 0; index < array.Length; index++)
                  {
                      retVal = (retVal << 8) + array[index];
                  }
              }
            }

            return retVal;
        }
    }
}