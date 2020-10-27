// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
namespace Microsoft.InformationProtection.Web.Models
{
    using System;
    using System.Collections.Generic;
    using Microsoft.Extensions.Configuration;
    using Microsoft.InformationProtection.Web.Models.Extensions;
    using sg = System.Globalization;
    public class KSPKeyStore : IKeyStore
    {
        private const string KeyType = "RSA";
        private const string Algorithm = "RS256";
        private Dictionary<string, Dictionary<string, KeyStoreData>> keys = new Dictionary<string, Dictionary<string, KeyStoreData>>();
        private Dictionary<string, string> activeKeys = new Dictionary<string, string>();

        public KSPKeyStore(IConfiguration configuration)
        {
            configuration.ThrowIfNull(nameof(configuration));

            var keysSection = configuration.GetSection("Keys");
            IAuthorizer keyAuth = null;

            if(!keysSection.Exists())
            {
                throw new System.ArgumentException("Keys section does not exist");
            }

            foreach(var testKey in keysSection.GetChildren())
            {
                List<string> roles = new List<string>();
                var validRoles = testKey.GetSection("AuthorizedRoles");
                var validEmails = testKey.GetSection("AuthorizedEmailAddress");

                if(validRoles != null && validRoles.Exists() &&
                   validEmails != null && validEmails.Exists())
                {
                    throw new System.ArgumentException("Both role and email authorizers cannot be used on the same test key");
                }

                if(validRoles != null && validRoles.Exists())
                {
                    RoleAuthorizer roleAuth = new RoleAuthorizer(configuration);
                    keyAuth = roleAuth;
                    foreach(var role in validRoles.GetChildren())
                    {
                        roleAuth.AddRole(role.Value);
                    }
                }
                else if(validEmails != null && validEmails.Exists())
                {
                    EmailAuthorizer emailAuth = new EmailAuthorizer();
                    keyAuth = emailAuth;
                    foreach(var email in validEmails.GetChildren())
                    {
                        emailAuth.AddEmail(email.Value);
                    }
                }

                int? expirationTimeInDays = null;
                var cacheTime = testKey["CacheExpirationInDays"];
                if(cacheTime != null)
                {
                    expirationTimeInDays = Convert.ToInt32(cacheTime, sg.CultureInfo.InvariantCulture);
                }

                var name = testKey["Name"];
                var id = testKey["Id"];
                var ksp = testKey["KSP"];

                if(name == null)
                {
                  throw new System.ArgumentException("The key must have a name");
                }

                if(id == null)
                {
                  throw new System.ArgumentException("The key must have an id");
                }

                if(ksp == null)
                {
                    throw new System.ArgumentException("The key must have a KSP");
                }

                CreateTestKey(
                    name,
                    id,
                    ksp,
                    KeyType,
                    Algorithm,
                    keyAuth,
                    expirationTimeInDays);
            }
        }

        public KeyStoreData GetActiveKey(string keyName)
        {
            Dictionary<string, KeyStoreData> keys;
            string activeKey;
            KeyStoreData foundKey;
            if(!this.keys.TryGetValue(keyName, out keys) || !activeKeys.TryGetValue(keyName, out activeKey) ||
                    !keys.TryGetValue(activeKey, out foundKey))
            {
                throw new ArgumentException("Key " + keyName + " not found");
            }

            return foundKey;
        }

        public KeyStoreData GetKey(string keyName, string keyId)
        {
            Dictionary<string, KeyStoreData> keys;
            KeyStoreData foundKey;
            if(!this.keys.TryGetValue(keyName, out keys) ||
                    !keys.TryGetValue(keyId, out foundKey))
            {
                throw new ArgumentException("Key " + keyName + "-" + keyId + " not found");
            }

            return foundKey;
        }

        private void CreateTestKey(
            string keyName,
            string keyId,
            string keyStorageProviderName,
            string keyType,
            string algorithm,
            IAuthorizer keyAuth,
            int? expirationTimeInDays)
        {
            keyAuth.ThrowIfNull(nameof(keyAuth));

            keys.Add(keyName, new Dictionary<string, KeyStoreData>());

            keys[keyName][keyId] = new KeyStoreData(
                                                new KSPKey(keyId, keyStorageProviderName),
                                                keyId,
                                                keyType,
                                                algorithm,
                                                keyAuth,
                                                expirationTimeInDays);
            //Multiple keys with the same name can be in the app settings, the first one for the current name is active, the rest have been rolled
            if(!activeKeys.ContainsKey(keyName))
            {
                activeKeys[keyName] = keyId;
            }
        }
    }
}