// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Test.OneDrive.Sdk.Authentication.Xamarin.Android
{
    using NUnit.Framework;
    using Microsoft.OneDrive.Sdk.Authentication;

    [TestFixture]
    public class CredentialVaultTests
    {
        private string ClientId;
        private string UserId;
        private byte[] SecondaryKeyBytes;
        private AccountSession AccountSession;
        private CredentialCache CredentialCache;
        private CredentialVault CredentialVault;

        [SetUp]
        public void Setup()
        {
            this.ClientId = "123456";
            this.UserId = "User1";
            this.SecondaryKeyBytes = new byte[] { 0x01, 0x02, 0x03 };
            this.AccountSession = new AccountSession()
            {
                AccessToken = "token",
                ClientId = this.ClientId,
                UserId = this.UserId
            };
            this.CredentialCache = new CredentialCache();
            this.CredentialCache.AddToCache(this.AccountSession);
            this.CredentialVault = new CredentialVault(this.ClientId);
            this.CredentialVault.AddCredentialCacheToVault(this.CredentialCache);
        }

        [Test]
        public void RetrieveCredentialCache()
        {
            CredentialCache returnedCache = new CredentialCache();
            var success = this.CredentialVault.RetrieveCredentialCache(returnedCache);

            Assert.IsTrue(success, "Failed to retrieve CredentialCache");
            Assert.AreEqual(
                this.CredentialCache.GetResultFromCache(this.ClientId, this.UserId).AccessToken,
                returnedCache.GetResultFromCache(this.ClientId, this.UserId).AccessToken,
                "Failed to get valid access token from CredentialCache");
        }

        [Test]
        public void DeleteStoredCredentialCache()
        {
            var success = this.CredentialVault.DeleteStoredCredentialCache();
            CredentialCache returnedCache = new CredentialCache();
            var failure = this.CredentialVault.RetrieveCredentialCache(returnedCache);

            Assert.IsTrue(success, "Failed to delete CredentialCache");
            Assert.IsFalse(failure, "CredentialCache was not deleted");
            Assert.IsNull(
                returnedCache.GetResultFromCache(this.ClientId, this.UserId),
                "Failed to clear previous credentials");
        }

        [Test]
        public void RetrieveCredentialCache_SecondaryKeyBytes()
        {
            var vault = new CredentialVault(this.ClientId, this.SecondaryKeyBytes);
            vault.AddCredentialCacheToVault(this.CredentialCache);
            CredentialCache returnedCache = new CredentialCache();
            var success = vault.RetrieveCredentialCache(returnedCache);

            Assert.IsTrue(success, "Failed to retrieve CredentialCache");
            Assert.AreEqual(
                this.CredentialCache.GetResultFromCache(this.ClientId, this.UserId).AccessToken,
                returnedCache.GetResultFromCache(this.ClientId, this.UserId).AccessToken,
                "Failed to get valid access token from CredentialCache");
        }
    }
}