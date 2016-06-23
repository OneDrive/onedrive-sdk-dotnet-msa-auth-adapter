// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Test.OneDrive.Sdk.Authentication.Desktop
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Net.Http;
    using System.Threading.Tasks;

    using Microsoft.Graph;
    using Microsoft.OneDrive.Sdk.Authentication;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using Mocks;
    using Moq;

    [TestClass]
    public class MsaAuthenticationProviderTests
    {
        private const string AppId = "12345";
        private const string ClientSecret = "client secret";
        private const string ReturnUrl = "https://localhost/return";
        private const string UserId = "user ID";

        private readonly string[] scopes = new string[] { "scope1", "scope2" };

        private MsaAuthenticationProvider authenticationProvider;
        private MockCredentialCache credentialCache;
        private MockHttpProvider httpProvider;
        private HttpResponseMessage httpResponseMessage;
        private MockSerializer serializer;
        private MockWebAuthenticationUi webAuthenticationUi;

        [TestInitialize]
        public virtual void Setup()
        {
            this.httpResponseMessage = new HttpResponseMessage();
            this.credentialCache = new MockCredentialCache();
            this.serializer = new MockSerializer();
            this.httpProvider = new MockHttpProvider(this.httpResponseMessage, this.serializer.Object);
            this.webAuthenticationUi = new MockWebAuthenticationUi();

            this.authenticationProvider = new MsaAuthenticationProvider(
                MsaAuthenticationProviderTests.AppId,
                MsaAuthenticationProviderTests.ClientSecret,
                MsaAuthenticationProviderTests.ReturnUrl,
                this.scopes,
                this.httpProvider.Object,
                this.credentialCache.Object);

            this.authenticationProvider.webAuthenticationUi = this.webAuthenticationUi.Object;
        }

        [TestCleanup]
        public virtual void Teardown()
        {
            this.httpResponseMessage.Dispose();
        }

        [TestMethod]
        public async Task AuthenticateRequestAsync()
        {
            var cachedAccountSession = new AccountSession
            {
                AccessToken = "token",
                ExpiresOnUtc = DateTimeOffset.UtcNow.AddMinutes(60),

            };

            this.authenticationProvider.CurrentAccountSession = cachedAccountSession;

            using (var httpRequestMessage = new HttpRequestMessage())
            {
                await this.authenticationProvider.AuthenticateRequestAsync(httpRequestMessage).ConfigureAwait(false);
                Assert.AreEqual(
                    string.Format("bearer {0}", cachedAccountSession.AccessToken),
                    httpRequestMessage.Headers.Authorization.ToString(),
                    "Unexpected authorization header set.");
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ServiceException))]
        public async Task AuthenticateRequestAsync_AuthenticateUserAsyncNotCalled()
        {
            using (var httpRequestMessage = new HttpRequestMessage())
            {
                try
                {
                    await this.authenticationProvider.AuthenticateRequestAsync(httpRequestMessage).ConfigureAwait(false);
                }
                catch (ServiceException serviceException)
                {
                    Assert.AreEqual(OAuthConstants.ErrorCodes.AuthenticationFailure, serviceException.Error.Code, "Unexpected error code.");
                    Assert.AreEqual(
                        "Unable to retrieve a valid account session for the user. Please call AuthenticateUserAsync to prompt the user to re-authenticate.",
                        serviceException.Error.Message,
                        "Unexpected error message.");

                    throw;
                }
            }
        }

        [TestMethod]
        public async Task AuthenticateUserAsync_AccountSessionFromCache()
        {
            var cachedAccountSession = new AccountSession
            {
                AccessToken = "token",
                ClientId = MsaAuthenticationProviderTests.AppId,
                ExpiresOnUtc = DateTimeOffset.UtcNow.AddMinutes(10),
            };

            this.credentialCache.Object.AddToCache(cachedAccountSession);

            await this.authenticationProvider.AuthenticateUserAsync().ConfigureAwait(false);

            Assert.IsNotNull(this.authenticationProvider.CurrentAccountSession, "No account session returned.");
            Assert.AreEqual(
                cachedAccountSession.AccessToken,
                this.authenticationProvider.CurrentAccountSession.AccessToken,
                "Unexpected access token returned.");

            Assert.AreEqual(
                cachedAccountSession.ExpiresOnUtc,
                this.authenticationProvider.CurrentAccountSession.ExpiresOnUtc,
                "Unexpected expiration returned.");
        }

        [TestMethod]
        public async Task AuthenticateUserAsync_CachedCurrentAccountSession()
        {
            var cachedAccountSession = new AccountSession
            {
                AccessToken = "token",
                ExpiresOnUtc = DateTimeOffset.UtcNow.AddMinutes(10),
            };

            this.authenticationProvider.CurrentAccountSession = cachedAccountSession;

            await this.authenticationProvider.AuthenticateUserAsync().ConfigureAwait(false);

            Assert.IsNotNull(this.authenticationProvider.CurrentAccountSession, "No account session returned.");
            Assert.AreEqual(
                cachedAccountSession.AccessToken,
                this.authenticationProvider.CurrentAccountSession.AccessToken,
                "Unexpected access token returned.");

            Assert.AreEqual(
                cachedAccountSession.ExpiresOnUtc,
                this.authenticationProvider.CurrentAccountSession.ExpiresOnUtc,
                "Unexpected expiration returned.");
        }

        [TestMethod]
        public async Task AuthenticateUserAsync_ExpiredResultNoRefreshToken()
        {
            var cachedAccountSession = new AccountSession
            {
                AccessToken = "token",
                ClientId = MsaAuthenticationProviderTests.AppId,
                ExpiresOnUtc = DateTimeOffset.UtcNow.AddMinutes(4),
                UserId = MsaAuthenticationProviderTests.UserId,
            };

            var refreshedAccountSession = new AccountSession
            {
                ClientId = "1",
                AccessToken = "token2",
            };

            this.credentialCache.Object.AddToCache(cachedAccountSession);

            this.authenticationProvider.CurrentAccountSession = cachedAccountSession;

            await this.AuthenticateWithCodeFlow(refreshedAccountSession).ConfigureAwait(false);

            this.credentialCache.Verify(cache => cache.OnGetResultFromCache(), Times.Once);
            this.credentialCache.Verify(cache => cache.OnDeleteFromCache(), Times.Once);
        }

        [TestMethod]
        public async Task AuthenticateUserAsync_RefreshToken()
        {
            var cachedAccountSession = new AccountSession
            {
                ClientId = "1",
                AccessToken = "token",
                ExpiresOnUtc = DateTimeOffset.UtcNow.AddMinutes(4),
                RefreshToken = "refresh",
            };

            var refreshedAccountSession = new AccountSession
            {
                ClientId = "1",
                AccessToken = "token2",
                RefreshToken = "refresh2",
            };

            this.authenticationProvider.CurrentAccountSession = cachedAccountSession;

            await this.AuthenticateWithRefreshToken(refreshedAccountSession).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task SignOutAsync()
        {
            var expectedSignOutUrl = string.Format(
                "{0}?client_id={1}&redirect_uri={2}",
                OAuthConstants.MicrosoftAccountSignOutUrl,
                MsaAuthenticationProviderTests.AppId,
                MsaAuthenticationProviderTests.ReturnUrl);

            var accountSession = new AccountSession
            {
                AccessToken = "accessToken",
                ClientId = "12345",
            };

            this.authenticationProvider.CurrentAccountSession = accountSession;

            await this.authenticationProvider.SignOutAsync().ConfigureAwait(false);

            this.webAuthenticationUi.Verify(
                webAuthenticationUi => webAuthenticationUi.AuthenticateAsync(
                    It.Is<Uri>(uri => uri.ToString().Equals(expectedSignOutUrl)),
                    It.Is<Uri>(uri => uri.ToString().Equals(MsaAuthenticationProviderTests.ReturnUrl))),
                Times.Once);

            Assert.IsNull(this.authenticationProvider.CurrentAccountSession, "Current account session not cleared.");
            
            this.credentialCache.Verify(cache => cache.OnDeleteFromCache(), Times.Once);
        }

        private Task AuthenticateWithCodeFlow(AccountSession refreshedAccountSession)
        {
            var tokenResponseDictionary = new Dictionary<string, string> { { "code", "code" } };

            this.webAuthenticationUi.Setup(webUi => webUi.AuthenticateAsync(
                It.Is<Uri>(uri => uri.ToString().Contains("response_type=code")),
                It.Is<Uri>(uri => uri.ToString().Equals(MsaAuthenticationProviderTests.ReturnUrl))))
                .Returns(
                    Task.FromResult<IDictionary<string, string>>(tokenResponseDictionary));

            return this.AuthenticateWithRefreshToken(refreshedAccountSession);
        }

        private async Task AuthenticateWithRefreshToken(AccountSession refreshedAccountSession)
        {
            using (var httpResponseMessage = new HttpResponseMessage())
            using (var responseStream = new MemoryStream())
            using (var streamContent = new StreamContent(responseStream))
            {
                httpResponseMessage.Content = streamContent;

                this.httpProvider.Setup(
                    provider => provider.SendAsync(
                        It.Is<HttpRequestMessage>(
                            request => request.RequestUri.ToString().Equals(OAuthConstants.MicrosoftAccountTokenServiceUrl))))
                    .Returns(Task.FromResult<HttpResponseMessage>(httpResponseMessage));

                this.serializer.Setup(
                    serializer => serializer.DeserializeObject<IDictionary<string, string>>(It.IsAny<Stream>()))
                    .Returns(new Dictionary<string, string>
                        {
                            { OAuthConstants.AccessTokenKeyName, refreshedAccountSession.AccessToken },
                            { OAuthConstants.RefreshTokenKeyName, refreshedAccountSession.RefreshToken },
                        });

                await this.authenticationProvider.AuthenticateUserAsync().ConfigureAwait(false);

                Assert.IsNotNull(this.authenticationProvider.CurrentAccountSession, "No account session returned.");
                Assert.AreEqual(
                    refreshedAccountSession.AccessToken,
                    this.authenticationProvider.CurrentAccountSession.AccessToken,
                    "Unexpected access token returned.");
                Assert.AreEqual(
                    refreshedAccountSession.RefreshToken,
                    this.authenticationProvider.CurrentAccountSession.RefreshToken,
                    "Unexpected refresh token returned.");
                Assert.AreEqual(
                    refreshedAccountSession.AccessToken,
                    this.authenticationProvider.CurrentAccountSession.AccessToken,
                    "Unexpected cached access token.");
                Assert.AreEqual(
                    refreshedAccountSession.RefreshToken,
                    this.authenticationProvider.CurrentAccountSession.RefreshToken,
                    "Unexpected cached refresh token.");
            }
        }
    }
}
