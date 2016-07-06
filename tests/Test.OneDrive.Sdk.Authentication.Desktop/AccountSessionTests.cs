// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Test.OneDrive.Sdk.Authentication.Desktop
{
    using System;
    using System.Collections.Generic;

    using Microsoft.OneDrive.Sdk.Authentication;
    using Microsoft.VisualStudio.TestTools.UnitTesting;

    [TestClass]
    public class AccountSessionTests
    {
        [TestMethod]
        public void VerifyClassInitialization()
        {
            var responseValues = new Dictionary<string, string>
            {
                { OAuthConstants.AccessTokenKeyName, "token" },
                { OAuthConstants.ExpiresInKeyName, "45" },
                { OAuthConstants.ScopeKeyName, "scope1%20scope2" },
                { OAuthConstants.UserIdKeyName, "1" },
                { OAuthConstants.RefreshTokenKeyName, "refresh" },
            };

            var accountSession = new AccountSession(responseValues);

            // Verify the expiration time is after now and somewhere between now and 45 seconds from now.
            // This accounts for delay in initialization until now.
            var dateTimeNow = DateTimeOffset.UtcNow;
            var dateTimeDifference = accountSession.ExpiresOnUtc - DateTimeOffset.UtcNow;
            Assert.IsTrue(accountSession.ExpiresOnUtc > dateTimeNow, "Unexpected expiration returned.");
            Assert.IsTrue(dateTimeDifference.Seconds <= 45, "Unexpected expiration returned.");

            Assert.IsNull(accountSession.ClientId, "Unexpected client ID.");
            Assert.AreEqual("token", accountSession.AccessToken, "Unexpected access token.");
            Assert.AreEqual("1", accountSession.UserId, "Unexpected user ID.");
            Assert.AreEqual("refresh", accountSession.RefreshToken, "Unexpected refresh token.");

            Assert.AreEqual(2, accountSession.Scopes.Length, "Unexpected number of scopes.");
            Assert.AreEqual("scope1", accountSession.Scopes[0], "Unexpected first scope.");
            Assert.AreEqual("scope2", accountSession.Scopes[1], "Unexpected second scope.");
        }

        [TestMethod]
        public void VerifyClassInitialization_SpecifyOptionalParameters()
        {
            var accountSession = new AccountSession(null, "1");

            Assert.AreEqual("1", accountSession.ClientId, "Unexpected client ID.");
        }
    }
}
