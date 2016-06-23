// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Test.OneDrive.Sdk.Authentication.Desktop
{
    using Microsoft.OneDrive.Sdk.Authentication;
    using Microsoft.VisualStudio.TestTools.UnitTesting;

    [TestClass]
    public class CredentialCacheKeyTests
    {
        [TestMethod]
        public void VerifyCacheKeyComparison_Equal()
        {
            var cacheKeyLower = new CredentialCacheKey
            {
                ClientId = "clientid",
                UserId = "abc",
            };

            var cacheKeyUpper = new CredentialCacheKey
            {
                ClientId = "CLIENTID",
                UserId = "ABC",
            };

            Assert.AreEqual(cacheKeyLower, cacheKeyUpper, "Cache key comparison failed.");
        }

        [TestMethod]
        public void VerifyCacheKeyComparison_NotEqual()
        {
            var cacheKeyLower = new CredentialCacheKey
            {
                UserId = "abc",
            };

            var cacheKeyUpper = new CredentialCacheKey
            {
                ClientId = "CLIENTID",
                UserId = "ABC",
            };

            Assert.AreNotEqual(cacheKeyLower, cacheKeyUpper, "Cache key comparison failed.");
        }
    }
}
