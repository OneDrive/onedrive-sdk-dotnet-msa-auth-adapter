// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.OneDrive.Sdk.Authentication
{
    using System;
    using System.IO;
    using System.Reflection;
    using System.Security.Cryptography;

    public class CredentialVault : ICredentialVault
    {
        static string applicationDataPath = null;
        public static string ApplicationDataPath
        {
            get
            {
                if (applicationDataPath == null)
                {
                    var enumtype=Type.GetType("System.Environment+SpecialFolder");
                    applicationDataPath = (string)(typeof(Environment).GetRuntimeMethod("GetFolderPath", new Type[] { enumtype }).Invoke(null, new object[] { Enum.Parse(enumtype, "ApplicationData") }));
                }
                return applicationDataPath;
            }
            set
            {
                applicationDataPath = value;
            }
        }
        private const string VaultNamePrefix = "OneDriveSDK_AuthAdapter";

        private string ClientId { get; set; }

        private string VaultFileName => $"{VaultNamePrefix}_{this.ClientId}.dat";

        private readonly byte[] _additionalEntropy;

        public CredentialVault(string clientId)
        {
            if (string.IsNullOrEmpty(clientId))
            {
                throw new ArgumentException("You must provide a clientId");
            }

            this.ClientId = clientId;
            this._additionalEntropy = null;
        }

        public CredentialVault(string clientId, byte[] secondaryKeyBytes) : this(clientId)
        {
            this._additionalEntropy = secondaryKeyBytes;
        }

        public void AddCredentialCacheToVault(CredentialCache credentialCache)
        {
            this.DeleteStoredCredentialCache();

            var cacheBlob = this.Protect(credentialCache.GetCacheBlob());
            using (var outStream = File.OpenWrite(GetVaultFilePath()))
            {
                outStream.Write(cacheBlob, 0, cacheBlob.Length);
            }
        }

        public bool RetrieveCredentialCache(CredentialCache credentialCache)
        {
            var filePath = this.GetVaultFilePath();

            if (File.Exists(filePath))
            {
                credentialCache.InitializeCacheFromBlob(this.Unprotect(File.ReadAllBytes(filePath)));
                return true;
            }

            return false;
        }

        public bool DeleteStoredCredentialCache()
        {
            var filePath = this.GetVaultFilePath();

            if (File.Exists(filePath))
            {
                File.Delete(filePath);
                return true;
            }

            return false;
        }

        private string GetVaultFilePath()
        {
            return Path.Combine(ApplicationDataPath, this.VaultFileName);
        }



        private byte[] Protect(byte[] data)
        {
            //  ProtectedData throws UnsupportedPlatform exception, utilizing ManagedProtection directly from Mono
            return ManagedProtection.Protect(data, this._additionalEntropy);
        }

        private byte[] Unprotect(byte[] protectedData)
        {
            //  ProtectedData throws UnsupportedPlatform exception, utilizing ManagedProtection directly from Mono
            return ManagedProtection.Unprotect(protectedData, this._additionalEntropy);
        }
    }
}