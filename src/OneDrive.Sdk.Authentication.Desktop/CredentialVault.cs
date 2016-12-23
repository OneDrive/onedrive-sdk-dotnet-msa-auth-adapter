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

        private IProtectedData protectedData;

        private IFile fileSystem;

        public CredentialVault(string clientId, byte[] secondaryKeyBytes = null, IFile fileSystem = null, IProtectedData protectedData = null)
        {
            if (string.IsNullOrEmpty(clientId))
            {
                throw new ArgumentException("You must provide a clientId");
            }

            this.ClientId = clientId;
            this.protectedData = protectedData ?? new ProtectedDataDefault(secondaryKeyBytes);
            this.fileSystem = fileSystem ?? new FileSystem();
        }

        public void AddCredentialCacheToVault(CredentialCache credentialCache)
        {
            this.DeleteStoredCredentialCache();

            var cacheBlob = this.protectedData.Protect(credentialCache.GetCacheBlob());
            using (var outStream = fileSystem.OpenWrite(this.GetVaultFilePath()))
            {
                outStream.Write(cacheBlob, 0, cacheBlob.Length);
            } 
        }

        public bool RetrieveCredentialCache(CredentialCache credentialCache)
        {
            var filePath = this.GetVaultFilePath();

            if (fileSystem.Exists(filePath))
            {
                credentialCache.InitializeCacheFromBlob(this.protectedData.Unprotect(fileSystem.ReadAllBytes(filePath)));
                return true;
            }

            return false;
        }

        public bool DeleteStoredCredentialCache()
        {
            var filePath = this.GetVaultFilePath();

            if (fileSystem.Exists(filePath))
            {
                fileSystem.Delete(filePath);
                return true;
            }

            return false;
        }

        private string GetVaultFilePath()
        {
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), this.VaultFileName);
        }

        public interface IFile
        {
            Stream OpenWrite(string path);
            bool Exists(string path);
            void Delete(string path);
            byte[] ReadAllBytes(string path);
        }

        private class FileSystem : IFile
        {
            public void Delete(string path)
            {
                File.Delete(path);
            }

            public bool Exists(string path)
            {
                return File.Exists(path);
            }

            public Stream OpenWrite(string path)
            {
                return File.OpenWrite(path);
            }

            public byte[] ReadAllBytes(string path)
            {
                return File.ReadAllBytes(path);
            }
        }

        public interface IProtectedData
        {
            byte[] Protect(byte[] data);
            byte[] Unprotect(byte[] protectedData);
        }

        public class ProtectedDataDefault : IProtectedData
        {
            public ProtectedDataDefault(byte[] additionalEntropy = null)
            {
                this._additionalEntropy = additionalEntropy;
            }

            private readonly byte[] _additionalEntropy;

            public byte[] Protect(byte[] data)
            {
                return ProtectedData.Protect(data, this._additionalEntropy, DataProtectionScope.CurrentUser);
            }

            public byte[] Unprotect(byte[] protectedData)
            {
                return ProtectedData.Unprotect(protectedData, this._additionalEntropy, DataProtectionScope.CurrentUser);
            }
        }
    }
}