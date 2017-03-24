// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.OneDrive.Sdk.Authentication
{
    using System;
    using System.IO;
    using System.Security.Cryptography;

    public class CredentialVault : ICredentialVault
    {
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
            string filePath = this.GetVaultFilePath();
            using (var outStream = File.OpenWrite(filePath))
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
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), this.VaultFileName);
        }

        private byte[] Protect(byte[] data)
        {
            return ProtectedData.Protect(data, this._additionalEntropy, DataProtectionScope.CurrentUser);
        }

        private byte[] Unprotect(byte[] protectedData)
        {
            return ProtectedData.Unprotect(protectedData, this._additionalEntropy, DataProtectionScope.CurrentUser);
        }
    }
}