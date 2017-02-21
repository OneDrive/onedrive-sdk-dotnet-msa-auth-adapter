// ------------------------------------------------------------------------------
//  Copyright (c) 2015 Microsoft Corporation
// 
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
// 
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
// 
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.
// ------------------------------------------------------------------------------

namespace Test.OneDrive.Sdk.Authentication.WinRT
{
    using System;
    using System.Threading.Tasks;

    using Microsoft.OneDrive.Sdk.Authentication;
    using Microsoft.VisualStudio.TestPlatform.UnitTestFramework;
    using Mocks;
    using System.Collections.Generic;
    using System.Net.Http;
    using System.IO;

    using Windows.Security.Authentication.Web;

    [TestClass]
    public class MsaAuthenticationProviderTests
    {
        private readonly string clientId = "client ID";
        private readonly string returnUrl = "https://localhost/return";
        private readonly string[] scopes = new string[] { "scopes" };        

        private MsaAuthenticationProvider authenticationProvider;
        private MockCredentialCache credentialCache;
        private MockWebAuthenticationUi webAuthenticationUi;

        private bool signOut;

        [TestInitialize]
        public void Setup()
        {
            this.credentialCache = new MockCredentialCache();
            this.webAuthenticationUi = new MockWebAuthenticationUi();
            this.webAuthenticationUi.OnAuthenticateAsync = this.OnAuthenticateAsync;

            this.authenticationProvider = new MsaAuthenticationProvider(
                this.clientId,
                this.returnUrl,
                this.scopes,
                this.credentialCache);

            this.authenticationProvider.webAuthenticationUi = this.webAuthenticationUi;
        }

        [TestMethod]
        public async Task GetAccountSessionAsync_ReturnUri()
        {
            const string code = "code";
            const string token = "token";

            this.signOut = false;
            this.webAuthenticationUi.responseValues = new Dictionary<string, string> { { OAuthConstants.CodeKeyName, code } };
            this.webAuthenticationUi.OnAuthenticateAsync = (Uri requestUri, Uri callbackUri) =>
            {
                Assert.IsTrue(requestUri.ToString().Contains("response_type=code"), "Unexpected request Uri.");
                Assert.IsTrue(callbackUri.ToString().Equals(this.returnUrl), "Unexpected callback Uri.");
            };

            using (var httpResponseMessage = new HttpResponseMessage())
            using (var responseStream = new MemoryStream())
            using (var streamContent = new StreamContent(responseStream))
            {
                httpResponseMessage.Content = streamContent;

                var mockSerializer = new MockSerializer();

                mockSerializer.OnDeserializeObjectStream = (Stream stream) =>
                {
                    mockSerializer.DeserializeObjectResponse = new Dictionary<string, string> { { OAuthConstants.AccessTokenKeyName, token } };
                };

                var httpProvider = new MockHttpProvider(httpResponseMessage, mockSerializer)
                {
                    OnSendAsync = (HttpRequestMessage requestMessage) =>
                    {
                        Assert.IsTrue(
                            requestMessage.RequestUri.ToString().Equals(OAuthConstants.MicrosoftAccountTokenServiceUrl),
                            "Unexpected token request URL.");
                    }
                };

                await this.authenticationProvider.AuthenticateUserAsync(httpProvider).ConfigureAwait(false);

                Assert.IsNotNull(this.authenticationProvider.CurrentAccountSession, "No account session returned.");
                Assert.AreEqual(token, this.authenticationProvider.CurrentAccountSession.AccessToken, "Unexpected token returned.");
            }
        }

        [TestMethod]
        public async Task GetAccountSessionAsync_SingleSignOn()
        {
            const string code = "code";
            const string token = "token";

            var applicationCallbackUrl = WebAuthenticationBroker.GetCurrentApplicationCallbackUri().ToString();

            this.signOut = false;

            this.webAuthenticationUi.responseValues = new Dictionary<string, string> { { OAuthConstants.CodeKeyName, code } };
            this.webAuthenticationUi.OnAuthenticateAsync = (Uri requestUri, Uri callbackUri) =>
            {
                Assert.IsTrue(requestUri.ToString().Contains("response_type=code"), "Unexpected request Uri.");
                Assert.IsTrue(callbackUri.ToString().Equals(applicationCallbackUrl), "Unexpected callback Uri.");
            };

            using (var httpResponseMessage = new HttpResponseMessage())
            using (var responseStream = new MemoryStream())
            using (var streamContent = new StreamContent(responseStream))
            {
                httpResponseMessage.Content = streamContent;

                var mockSerializer = new MockSerializer();

                mockSerializer.OnDeserializeObjectStream = (Stream stream) =>
                {
                    mockSerializer.DeserializeObjectResponse = new Dictionary<string, string> { { OAuthConstants.AccessTokenKeyName, token } };
                };

                var httpProvider = new MockHttpProvider(httpResponseMessage, mockSerializer)
                {
                    OnSendAsync = (HttpRequestMessage requestMessage) =>
                    {
                        Assert.IsTrue(
                            requestMessage.RequestUri.ToString().Equals(OAuthConstants.MicrosoftAccountTokenServiceUrl),
                            "Unexpected token request URL.");
                    }
                };

                this.authenticationProvider = new MsaAuthenticationProvider(
                    this.clientId,
                    /* returnUrl */ null,
                    this.scopes,
                    this.credentialCache);

                this.authenticationProvider.webAuthenticationUi = this.webAuthenticationUi;

                await this.authenticationProvider.AuthenticateUserAsync(httpProvider).ConfigureAwait(false);

                Assert.IsNotNull(this.authenticationProvider.CurrentAccountSession, "No account session returned.");
                Assert.AreEqual(token, this.authenticationProvider.CurrentAccountSession.AccessToken, "Unexpected token returned.");
            }
        }

        [TestMethod]
        public async Task SignOutAsync_ReturnUri()
        {
            this.signOut = true;
            var expectedSignOutUrl = string.Format(
                "{0}?client_id={1}&redirect_uri={2}",
                OAuthConstants.MicrosoftAccountSignOutUrl,
                this.clientId,
                this.returnUrl);

            this.webAuthenticationUi.OnAuthenticateAsync = (Uri requestUri, Uri callbackUri) =>
            {
                Assert.AreEqual(expectedSignOutUrl, requestUri.ToString(), "Unexpected request Uri.");
                Assert.AreEqual(this.returnUrl, callbackUri.ToString(), "Unexpected callback Uri.");
            };

            var accountSession = new AccountSession
            {
                AccessToken = "accessToken",
                ClientId = "12345",
            };

            this.authenticationProvider.CurrentAccountSession = accountSession;

            await this.authenticationProvider.SignOutAsync().ConfigureAwait(false);

            Assert.IsNull(this.authenticationProvider.CurrentAccountSession, "Current account session not cleared.");
            Assert.IsTrue(this.credentialCache.DeleteFromCacheCalled, "DeleteFromCache not called.");
        }

        [TestMethod]
        public async Task SignOutAsync_SingleSignOn()
        {
            var applicationCallbackUrl = WebAuthenticationBroker.GetCurrentApplicationCallbackUri().ToString();

            this.signOut = true;
            var expectedSignOutUrl = string.Format(
                "{0}?client_id={1}&redirect_uri={2}",
                OAuthConstants.MicrosoftAccountSignOutUrl,
                this.clientId,
                applicationCallbackUrl);

            this.webAuthenticationUi.OnAuthenticateAsync = (Uri requestUri, Uri callbackUri) =>
            {
                Assert.AreEqual(expectedSignOutUrl, requestUri.ToString(), "Unexpected request Uri.");
                Assert.AreEqual(applicationCallbackUrl, callbackUri.ToString(), "Unexpected callback Uri.");
            };

            var accountSession = new AccountSession
            {
                AccessToken = "accessToken",
                ClientId = "12345",
            };

            this.authenticationProvider = new MsaAuthenticationProvider(
                this.clientId,
                /* returnUrl */ null,
                this.scopes,
                this.credentialCache);

            this.authenticationProvider.webAuthenticationUi = this.webAuthenticationUi;
            this.authenticationProvider.CurrentAccountSession = accountSession;

            await this.authenticationProvider.SignOutAsync().ConfigureAwait(false);

            Assert.IsNull(this.authenticationProvider.CurrentAccountSession, "Current account session not cleared.");
            Assert.IsTrue(this.credentialCache.DeleteFromCacheCalled, "DeleteFromCache not called.");
        }

        private void OnAuthenticateAsync(Uri requestUri, Uri callbackUri)
        {
            if (string.IsNullOrEmpty(this.returnUrl))
            {
                Assert.IsNull(callbackUri, "Unexpected callbackUri set.");
            }
            else
            {
                Assert.AreEqual(this.returnUrl, callbackUri.ToString(), "Unexpected callbackUri set.");
            }

            if (this.signOut)
            {
                Assert.IsTrue(requestUri.ToString().StartsWith(OAuthConstants.MicrosoftAccountSignOutUrl), "Unexpected request URI.");
            }
            else
            {
                Assert.IsTrue(requestUri.ToString().StartsWith(OAuthConstants.MicrosoftAccountAuthenticationServiceUrl), "Unexpected authentication URI.");
            }
        }
    }
}
