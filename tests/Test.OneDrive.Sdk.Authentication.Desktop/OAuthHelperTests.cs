// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Test.OneDrive.Sdk.Authentication.Desktop
{
    using System;
    using System.Net.Http;
    using System.Threading.Tasks;

    using Microsoft.Graph;
    using Microsoft.OneDrive.Sdk.Authentication;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using Mocks;
    using Moq;

    [TestClass]
    public class OAuthHelperTests
    {
        private const string ClientId = "12345";
        private const string ClientSecret = "client secret";
        private const string ReturnUrl = "https://localhost/return";
        private const string UserId = "user ID";

        private readonly string[] scopes = new string[] { "scope1", "scope2" };

        private MockCredentialCache credentialCache;
        private MockHttpProvider httpProvider;
        private HttpResponseMessage httpResponseMessage;
        private MockSerializer serializer;
        private MockWebAuthenticationUi webAuthenticationUi;
        private OAuthHelper oAuthHelper;

        [TestInitialize]
        public virtual void Setup()
        {
            this.httpResponseMessage = new HttpResponseMessage();
            this.credentialCache = new MockCredentialCache();
            this.serializer = new MockSerializer();
            this.httpProvider = new MockHttpProvider(this.httpResponseMessage, this.serializer.Object);
            this.webAuthenticationUi = new MockWebAuthenticationUi();

            this.oAuthHelper = new OAuthHelper();
        }

        [TestCleanup]
        public virtual void Teardown()
        {
            this.httpResponseMessage.Dispose();
        }

        [TestMethod]
        public async Task GetAuthorizationCodeAsync_NullWebAuthenticationUi()
        {
            var code = await this.oAuthHelper.GetAuthorizationCodeAsync(
                OAuthHelperTests.ClientId,
                OAuthHelperTests.ReturnUrl,
                this.scopes,
                this.webAuthenticationUi.Object,
                null).ConfigureAwait(false);

            Assert.IsNull(code, "Unexpected code returned.");
        }

        [TestMethod]
        public void GetCodeRedemptionRequestBody_ClientSecret()
        {
            var code = "code";
            var requestBodyString = this.oAuthHelper.GetAuthorizationCodeRedemptionRequestBody(
                code,
                OAuthHelperTests.ClientId,
                OAuthHelperTests.ReturnUrl,
                this.scopes,
                OAuthHelperTests.ClientSecret);

            Assert.IsTrue(requestBodyString.Contains(string.Concat("code=", code)), "Code not set correctly.");
            Assert.IsTrue(
                requestBodyString.Contains(string.Concat("client_secret=", OAuthHelperTests.ClientSecret)),
                "Client secret not set correctly.");
        }

        [TestMethod]
        public void GetCodeRedemptionRequestBody_NoClientSecret()
        {
            var code = "code";
            var requestBodyString = this.oAuthHelper.GetAuthorizationCodeRedemptionRequestBody(
                code,
                OAuthHelperTests.ClientId,
                OAuthHelperTests.ReturnUrl,
                this.scopes);

            Assert.IsTrue(requestBodyString.Contains(string.Concat("code=", code)), "Code not set correctly.");
            Assert.IsFalse(requestBodyString.Contains("client_secret"), "Client secret set.");
        }

        [TestMethod]
        public void GetRefreshTokenRequestBody_ClientSecret()
        {
            var token = "token";
            var requestBodyString = this.oAuthHelper.GetRefreshTokenRequestBody(
                token,
                OAuthHelperTests.ClientId,
                OAuthHelperTests.ReturnUrl,
                this.scopes,
                OAuthHelperTests.ClientSecret);

            Assert.IsTrue(requestBodyString.Contains(string.Concat("refresh_token=", token)), "Token not set correctly.");
            Assert.IsTrue(
                requestBodyString.Contains(string.Concat("client_secret=", OAuthHelperTests.ClientSecret)),
                "Client secret not set correctly.");
        }

        [TestMethod]
        public void GetRefreshTokenRequestBody_NoClientSecret()
        {
            var token = "token";
            var requestBodyString = this.oAuthHelper.GetRefreshTokenRequestBody(
                token,
                OAuthHelperTests.ClientId,
                OAuthHelperTests.ReturnUrl,
                this.scopes);

            Assert.IsTrue(requestBodyString.Contains(string.Concat("refresh_token=", token)), "Token not set correctly.");
            Assert.IsFalse(requestBodyString.Contains("client_secret"), "Client secret set.");
        }

        [TestMethod]
        [ExpectedException(typeof(ServiceException))]
        public async Task RedeemAuthorizationCode_AuthorizationCodeRequired()
        {
            try
            {
                await this.oAuthHelper.RedeemAuthorizationCodeAsync(
                    /* authorizationCode */ null,
                    OAuthHelperTests.ClientId,
                    OAuthHelperTests.ClientSecret,
                    OAuthHelperTests.ReturnUrl,
                    this.scopes,
                    this.httpProvider.Object).ConfigureAwait(false);
            }
            catch (ServiceException serviceException)
            {
                Assert.AreEqual(OAuthConstants.ErrorCodes.AuthenticationFailure, serviceException.Error.Code, "Unexpected error code.");
                Assert.AreEqual(
                    "Authorization code is required to redeem.",
                    serviceException.Error.Message,
                    "Unexpected error message.");

                throw;
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ServiceException))]
        public async Task RedeemRefreshToken_RefreshTokenRequired()
        {
            try
            {
                await this.oAuthHelper.RedeemRefreshTokenAsync(
                    /* refreshToken */ null,
                    OAuthHelperTests.ClientId,
                    OAuthHelperTests.ReturnUrl,
                    this.scopes).ConfigureAwait(false);
            }
            catch (ServiceException serviceException)
            {
                Assert.AreEqual(OAuthConstants.ErrorCodes.AuthenticationFailure, serviceException.Error.Code, "Unexpected error code.");
                Assert.AreEqual(
                    "Refresh token is required to redeem.",
                    serviceException.Error.Message,
                    "Unexpected error message.");

                throw;
            }
        }
    }
}
