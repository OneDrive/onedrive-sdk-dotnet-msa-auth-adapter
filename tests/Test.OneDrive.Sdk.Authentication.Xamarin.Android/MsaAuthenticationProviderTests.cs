// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Test.OneDrive.Sdk.Authentication.Xamarin.Android
{
    using System;
    using System.Net.Http;
    using System.Threading.Tasks;
    using NUnit.Framework;
    using Microsoft.Graph;
    using Microsoft.OneDrive.Sdk.Authentication;
    using Test.OneDrive.Sdk.Authentication.Xamarin.Android.Mocks;

    [TestFixture]
    public class MsaAuthenticationProviderTests
    {
        private string ClientId;
        private string ClientSecret;
        private string ReturnUrl;
        private string[] Scopes;
        private CredentialCache CredentialCache;
        private MockSerializer Serializer;
        private HttpResponseMessage ResponseMessage;
        private MockHttpProvider HttpProvider;
        private MockWebAuthenticationUi WebAuthenticationUi;
        private MsaAuthenticationProvider AuthenticationProvider;

        [SetUp]
        public void Setup()
        {
            this.ClientId = "123456";
            this.ClientSecret = "QWERTY";
            this.ReturnUrl = "http://www.returnurl.com";
            this.Scopes = new string[] { "Scope1", "Scope2" };
            this.CredentialCache = new CredentialCache();
            this.Serializer = new MockSerializer();
            this.ResponseMessage = new HttpResponseMessage();
            this.HttpProvider = new MockHttpProvider(this.ResponseMessage, this.Serializer);
            this.WebAuthenticationUi = new MockWebAuthenticationUi();
            this.AuthenticationProvider = new MsaAuthenticationProvider(
                                                this.ClientId,
                                                this.ClientSecret,
                                                this.ReturnUrl,
                                                this.Scopes,
                                                this.CredentialCache,
                                                this.WebAuthenticationUi);
        }

        [Test]
        public async Task AuthenticateRequestAsync()
        {
            var accountSession = new AccountSession
                                {
                                    AccessToken = "token",
                                    ExpiresOnUtc = DateTimeOffset.UtcNow.AddMinutes(60)
                                };

            this.AuthenticationProvider.CurrentAccountSession = accountSession;

            using (HttpRequestMessage request = new HttpRequestMessage())
            {
                await this.AuthenticationProvider.AuthenticateRequestAsync(request);
                Assert.AreEqual(
                    string.Format("{0} {1}", OAuthConstants.Headers.Bearer, accountSession.AccessToken),
                    request.Headers.Authorization.ToString(),
                    "Unexpected authorization header set.");
            }
        }

        [Test]
        [ExpectedException(typeof(ServiceException))]
        public async Task AuthenticateRequestAsync_AuthenticateUserAsyncNotCalled()
        {
            using (var httpRequestMessage = new HttpRequestMessage())
            {
                try
                {
                    await this.AuthenticationProvider.AuthenticateRequestAsync(httpRequestMessage);
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

        [Test]
        public async Task AuthenticateUserAsync_AccountSessionFromCache()
        {
            var cachedAccountSession = new AccountSession
            {
                AccessToken = "token",
                ClientId = this.ClientId,
                ExpiresOnUtc = DateTimeOffset.UtcNow.AddMinutes(10),
            };

            this.CredentialCache.AddToCache(cachedAccountSession);


            await this.AuthenticationProvider.AuthenticateUserAsync(this.HttpProvider);

            Assert.IsNotNull(this.AuthenticationProvider.CurrentAccountSession, "No account session returned.");
            Assert.AreEqual(
                cachedAccountSession.AccessToken,
                this.AuthenticationProvider.CurrentAccountSession.AccessToken,
                "Unexpected access token returned.");

            Assert.AreEqual(
                cachedAccountSession.ExpiresOnUtc,
                this.AuthenticationProvider.CurrentAccountSession.ExpiresOnUtc,
                "Unexpected expiration returned.");
        }

        [Test]
        public async Task AuthenticateUserAsync_CachedCurrentAccountSession()
        {
            var cachedAccountSession = new AccountSession
            {
                AccessToken = "token",
                ExpiresOnUtc = DateTimeOffset.UtcNow.AddMinutes(10),
            };

            this.AuthenticationProvider.CurrentAccountSession = cachedAccountSession;

            await this.AuthenticationProvider.AuthenticateUserAsync(this.HttpProvider);

            Assert.IsNotNull(this.AuthenticationProvider.CurrentAccountSession, "No account session returned.");
            Assert.AreEqual(
                cachedAccountSession.AccessToken,
                this.AuthenticationProvider.CurrentAccountSession.AccessToken,
                "Unexpected access token returned.");

            Assert.AreEqual(
                cachedAccountSession.ExpiresOnUtc,
                this.AuthenticationProvider.CurrentAccountSession.ExpiresOnUtc,
                "Unexpected expiration returned.");
        }

    }
}