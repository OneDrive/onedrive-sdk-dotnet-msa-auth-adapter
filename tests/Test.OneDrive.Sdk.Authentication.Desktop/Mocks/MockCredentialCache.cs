// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Test.OneDrive.Sdk.Authentication.Desktop.Mocks
{
    using Microsoft.OneDrive.Sdk.Authentication;
    using Moq;

    public class MockCredentialCache : Mock<TestCredentialCache>
    {
        public MockCredentialCache()
            : base(MockBehavior.Strict)
        {
            this.SetupAllProperties();
            this.Setup(cache => cache.OnAddToCache());
            this.Setup(cache => cache.OnDeleteFromCache());
            this.Setup(cache => cache.OnGetResultFromCache());
            this.Setup(cache => cache.InitializeCacheFromBlob(It.IsAny<byte[]>()));
        }
    }

    public class TestCredentialCache : CredentialCache
    {
        public virtual void OnAddToCache()
        {
        }

        public virtual void OnDeleteFromCache()
        {
        }

        public virtual void OnGetResultFromCache()
        {
        }

        internal override void AddToCache(AccountSession accountSession)
        {
            this.OnAddToCache();
            base.AddToCache(accountSession);
        }

        internal override void DeleteFromCache(AccountSession accountSession)
        {
            this.OnDeleteFromCache();
            base.DeleteFromCache(accountSession);
        }

        internal override AccountSession GetResultFromCache(string clientId, string userId)
        {
            this.OnGetResultFromCache();
            return base.GetResultFromCache(clientId, userId);
        }
    }
}
