// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Test.OneDrive.Sdk.Authentication.Desktop
{
    using System;
    using System.Collections.Generic;
    using System.Net.Http;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;

    using Microsoft.Graph;
    using Microsoft.IdentityModel.Clients.ActiveDirectory;
    using Microsoft.OneDrive.Sdk.Authentication;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using Mocks;
    using Moq;

    [TestClass]
    public class AdalAuthenticationProviderTests : AuthenticationTestBase
    {
        [TestInitialize]
        public override void Setup()
        {
            base.Setup();
        }

        [TestMethod]
        [ExpectedException(typeof(ServiceException))]
        public void AdalAuthenticationProvider_ClientIdRequired()
        {
            try
            {
                var authenticationProvider = new AdalAuthenticationProvider(null, null);
            }
            catch (ServiceException exception)
            {
                Assert.IsNotNull(exception.Error, "Error not set in exception.");
                Assert.IsTrue(exception.IsMatch(OAuthConstants.ErrorCodes.AuthenticationFailure), "Unexpected error code returned.");
                Assert.AreEqual("AdalAuthenticationProvider requires a client ID for authenticating users.",
                    exception.Error.Message,
                    "Unexpected error message returned.");
                Assert.IsNull(exception.InnerException, "Unexpected inner exception.");

                throw;
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ServiceException))]
        public async Task AuthenticateRequestAsync_AuthenticateSilentlyFailed()
        {
            var innerException = new Exception();
            var cachedAccountSession = new AccountSession
            {
                AccessToken = "expiredToken",
                ExpiresOnUtc = DateTimeOffset.UtcNow,
            };

            var mockAuthenticationContextWrapper = new MockAuthenticationContextWrapper();
            mockAuthenticationContextWrapper.Setup(wrapper => wrapper.AcquireTokenSilentAsync(
                It.Is<string>(resource => resource.Equals(AuthenticationTestBase.ServiceResourceId)),
                It.Is<string>(clientId => clientId.Equals(AuthenticationTestBase.ClientId)),
                UserIdentifier.AnyUser))
                .Throws(innerException);

            var authenticationProvider = new AdalAuthenticationProvider(
                AuthenticationTestBase.ClientId,
                AuthenticationTestBase.ReturnUrl,
                mockAuthenticationContextWrapper.Object)
            {
                CurrentAccountSession = cachedAccountSession,
                currentServiceResourceId = AuthenticationTestBase.ServiceResourceId,
            };

            using (var httpRequestMessage = new HttpRequestMessage())
            {
                try
                {
                    await authenticationProvider.AuthenticateRequestAsync(httpRequestMessage);
                }
                catch (ServiceException exception)
                {
                    Assert.IsNotNull(exception.Error, "Error not set in exception.");
                    Assert.IsTrue(exception.IsMatch(OAuthConstants.ErrorCodes.AuthenticationFailure), "Unexpected error code returned.");
                    Assert.AreEqual("Failed to retrieve a cached account session or silently retrieve a new access token. Please call AuthenticateUserAsync...() again to re-authenticate.",
                        exception.Error.Message,
                        "Unexpected error message returned.");
                    Assert.AreEqual(innerException, exception.InnerException, "Unexpected inner exception.");

                    throw;
                }
            }
        }

        [TestMethod]
        public async Task AuthenticateRequestAsync_CachedAccountSession()
        {
            var cachedAccountSession = new AccountSession
            {
                AccessToken = "token",
                ExpiresOnUtc = DateTimeOffset.UtcNow.AddHours(1),
            };

            var authenticationProvider = new AdalAuthenticationProvider(AuthenticationTestBase.ClientId, AuthenticationTestBase.ReturnUrl)
            {
                CurrentAccountSession = cachedAccountSession,
            };

            using (var httpRequestMessage = new HttpRequestMessage())
            {
                await authenticationProvider.AuthenticateRequestAsync(httpRequestMessage);
                Assert.AreEqual(
                    string.Format("{0} {1}", OAuthConstants.Headers.Bearer, cachedAccountSession.AccessToken),
                    httpRequestMessage.Headers.Authorization.ToString(),
                    "Unexpected authorization header set.");
            }
        }

        [TestMethod]
        public async Task AuthenticateRequestAsync_CachedCurrentAccountSessionExpiring()
        {
            var cachedAccountSession = new AccountSession
            {
                AccessToken = "expiredToken",
                ExpiresOnUtc = DateTimeOffset.UtcNow,
            };

            var mockAuthenticationResult = new MockAuthenticationResult();
            mockAuthenticationResult.SetupGet(result => result.AccessToken).Returns("token");
            mockAuthenticationResult.SetupGet(result => result.AccessTokenType).Returns((string)null);
            mockAuthenticationResult.SetupGet(result => result.ExpiresOn).Returns(DateTimeOffset.UtcNow.AddHours(1));

            var mockAuthenticationContextWrapper = new MockAuthenticationContextWrapper();
            mockAuthenticationContextWrapper.Setup(wrapper => wrapper.AcquireTokenSilentAsync(
                It.Is<string>(resource => resource.Equals(AuthenticationTestBase.ServiceResourceId)),
                It.Is<string>(clientId => clientId.Equals(AuthenticationTestBase.ClientId)),
                UserIdentifier.AnyUser))
                .Returns(Task.FromResult(mockAuthenticationResult.Object));

            var authenticationProvider = new AdalAuthenticationProvider(
                AuthenticationTestBase.ClientId,
                AuthenticationTestBase.ReturnUrl,
                mockAuthenticationContextWrapper.Object)
            {
                CurrentAccountSession = cachedAccountSession,
                currentServiceResourceId = AuthenticationTestBase.ServiceResourceId,
            };

            using (var httpRequestMessage = new HttpRequestMessage())
            {
                await authenticationProvider.AuthenticateRequestAsync(httpRequestMessage);
                Assert.AreEqual(
                    string.Format("{0} token", OAuthConstants.Headers.Bearer),
                    httpRequestMessage.Headers.Authorization.ToString(),
                    "Unexpected authorization header set.");
            }
        }

        [TestMethod]
        public async Task AuthenticateRequestAsync_DifferentType()
        {
            var cachedAccountSession = new AccountSession
            {
                AccessToken = "token",
                AccessTokenType = "test",
                ExpiresOnUtc = DateTimeOffset.UtcNow.AddHours(1),
            };

            var authenticationProvider = new AdalAuthenticationProvider(AuthenticationTestBase.ClientId, AuthenticationTestBase.ReturnUrl)
            {
                CurrentAccountSession = cachedAccountSession,
            };

            using (var httpRequestMessage = new HttpRequestMessage())
            {
                await authenticationProvider.AuthenticateRequestAsync(httpRequestMessage);
                Assert.AreEqual(
                    string.Format("{0} {1}", cachedAccountSession.AccessTokenType, cachedAccountSession.AccessToken),
                    httpRequestMessage.Headers.Authorization.ToString(),
                    "Unexpected authorization header set.");
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ServiceException))]
        public async Task AuthenticateRequestAsync_MustAuthenticateFirst()
        {
            var cachedAccountSession = new AccountSession
            {
                AccessToken = "token",
                ExpiresOnUtc = DateTimeOffset.UtcNow.AddHours(1),
            };

            var authenticationProvider = new AdalAuthenticationProvider(AuthenticationTestBase.ClientId, AuthenticationTestBase.ReturnUrl);

            using (var httpRequestMessage = new HttpRequestMessage())
            {
                try
                {
                    await authenticationProvider.AuthenticateRequestAsync(httpRequestMessage);
                }
                catch (ServiceException exception)
                {
                    Assert.IsNotNull(exception.Error, "Error not set in exception.");
                    Assert.IsTrue(exception.IsMatch(OAuthConstants.ErrorCodes.AuthenticationFailure), "Unexpected error code returned.");
                    Assert.AreEqual("Please call one of the AuthenticateUserAsync...() methods to authenticate the user before trying to authenticate a request.",
                        exception.Error.Message,
                        "Unexpected error message returned.");
                    Assert.IsNull(exception.InnerException, "Unexpected inner exception.");

                    throw;
                }
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ServiceException))]
        public async Task AuthenticateRequestAsync_NullAuthenticationResult()
        {
            var cachedAccountSession = new AccountSession
            {
                AccessToken = "expiredToken",
                ExpiresOnUtc = DateTimeOffset.UtcNow,
            };

            var mockAuthenticationContextWrapper = new MockAuthenticationContextWrapper();
            mockAuthenticationContextWrapper.Setup(wrapper => wrapper.AcquireTokenSilentAsync(
                It.Is<string>(resource => resource.Equals(AuthenticationTestBase.ServiceResourceId)),
                It.Is<string>(clientId => clientId.Equals(AuthenticationTestBase.ClientId)),
                UserIdentifier.AnyUser))
                .Returns(Task.FromResult<IAuthenticationResult>(null));

            var authenticationProvider = new AdalAuthenticationProvider(
                AuthenticationTestBase.ClientId,
                AuthenticationTestBase.ReturnUrl,
                mockAuthenticationContextWrapper.Object)
            {
                CurrentAccountSession = cachedAccountSession,
                currentServiceResourceId = AuthenticationTestBase.ServiceResourceId,
            };

            using (var httpRequestMessage = new HttpRequestMessage())
            {
                try
                {
                    await authenticationProvider.AuthenticateRequestAsync(httpRequestMessage);
                }
                catch (ServiceException exception)
                {
                    Assert.IsNotNull(exception.Error, "Error not set in exception.");
                    Assert.IsTrue(exception.IsMatch(OAuthConstants.ErrorCodes.AuthenticationFailure), "Unexpected error code returned.");
                    Assert.AreEqual("Failed to retrieve a cached account session or silently retrieve a new access token. Please call AuthenticateUserAsync...() again to re-authenticate.",
                        exception.Error.Message,
                        "Unexpected error message returned.");
                    Assert.IsNull(exception.InnerException, "Unexpected inner exception.");

                    throw;
                }
            }
        }

        [TestMethod]
        public async Task AuthenticateAsync_RefreshExpiringCachedSession()
        {
            var cachedAccountSession = new AccountSession
            {
                AccessToken = "expiredToken",
                ExpiresOnUtc = DateTimeOffset.UtcNow,
                RefreshToken = "refresh",
            };

            var mockAuthenticationResult = new MockAuthenticationResult();
            mockAuthenticationResult.SetupGet(result => result.AccessToken).Returns("token");
            mockAuthenticationResult.SetupGet(result => result.AccessTokenType).Returns((string)null);
            mockAuthenticationResult.SetupGet(result => result.ExpiresOn).Returns(DateTimeOffset.UtcNow.AddHours(1));

            var mockAuthenticationContextWrapper = new MockAuthenticationContextWrapper();
            mockAuthenticationContextWrapper.Setup(wrapper => wrapper.AcquireTokenByRefreshTokenAsync(
                It.Is<string>(refreshToken => refreshToken.Equals(cachedAccountSession.RefreshToken)),
                It.Is<string>(clientId => clientId.Equals(AuthenticationTestBase.ClientId)),
                It.Is<string>(resource => resource.Equals(AuthenticationTestBase.ServiceResourceId))))
                .Returns(Task.FromResult(mockAuthenticationResult.Object));

            var authenticationProvider = new AdalAuthenticationProvider(
                AuthenticationTestBase.ClientId,
                AuthenticationTestBase.ReturnUrl,
                mockAuthenticationContextWrapper.Object)
            {
                CurrentAccountSession = cachedAccountSession,
                currentServiceResourceId = AuthenticationTestBase.ServiceResourceId,
            };

            using (var httpRequestMessage = new HttpRequestMessage())
            {
                await authenticationProvider.AuthenticateRequestAsync(httpRequestMessage);
                Assert.AreEqual(
                    string.Format("{0} token", OAuthConstants.Headers.Bearer),
                    httpRequestMessage.Headers.Authorization.ToString(),
                    "Unexpected authorization header set.");
            }
        }

        [TestMethod]
        public async Task AuthenticateUserAsync_AuthenticateSilentlyClientCertificate()
        {
            var clientCertificate = new X509Certificate2(@"Certs\testwebapplication.pfx", "password");

            var mockAuthenticationResult = new MockAuthenticationResult();
            mockAuthenticationResult.SetupGet(result => result.AccessToken).Returns("token");
            mockAuthenticationResult.SetupGet(result => result.AccessTokenType).Returns("type");
            mockAuthenticationResult.SetupGet(result => result.ExpiresOn).Returns(DateTimeOffset.UtcNow);

            var mockAuthenticationContextWrapper = new MockAuthenticationContextWrapper();

            mockAuthenticationContextWrapper.Setup(wrapper => wrapper.AcquireTokenSilentAsync(
                It.Is<string>(resource => resource.Equals(AuthenticationTestBase.ServiceResourceId)),
                It.Is<ClientAssertionCertificate>(certificate =>
                    certificate.Certificate == clientCertificate &&
                    certificate.ClientId.Equals(AuthenticationTestBase.ClientId)),
                UserIdentifier.AnyUser)).Returns(Task.FromResult(mockAuthenticationResult.Object));

            var authenticationProvider = new AdalAuthenticationProvider(
                AuthenticationTestBase.ClientId,
                clientCertificate,
                AuthenticationTestBase.ReturnUrl,
                mockAuthenticationContextWrapper.Object);

            await this.AuthenticateUserAsync(
                authenticationProvider,
                mockAuthenticationResult.Object);
        }

        [TestMethod]
        public async Task AuthenticateUserAsync_AuthenticateSilently()
        {
            var mockAuthenticationResult = new MockAuthenticationResult();
            mockAuthenticationResult.SetupGet(result => result.AccessToken).Returns("token");
            mockAuthenticationResult.SetupGet(result => result.AccessTokenType).Returns("type");
            mockAuthenticationResult.SetupGet(result => result.ExpiresOn).Returns(DateTimeOffset.UtcNow);

            var mockAuthenticationContextWrapper = new MockAuthenticationContextWrapper();
            mockAuthenticationContextWrapper.Setup(wrapper => wrapper.AcquireTokenSilentAsync(
                It.Is<string>(resource => resource.Equals(AuthenticationTestBase.ServiceResourceId)),
                It.Is<string>(clientId => clientId.Equals(AuthenticationTestBase.ClientId)),
                UserIdentifier.AnyUser)).Returns(Task.FromResult(mockAuthenticationResult.Object));

            var authenticationProvider = new AdalAuthenticationProvider(
                AuthenticationTestBase.ClientId,
                AuthenticationTestBase.ReturnUrl,
                mockAuthenticationContextWrapper.Object);

            await this.AuthenticateUserAsync(
                authenticationProvider,
                mockAuthenticationResult.Object);
        }

        [TestMethod]
        public async Task AuthenticateUserAsync_AuthenticateSilently_ClientCredential()
        {
            var clientSecret = "client secret";

            var mockAuthenticationResult = new MockAuthenticationResult();
            mockAuthenticationResult.SetupGet(result => result.AccessToken).Returns("token");
            mockAuthenticationResult.SetupGet(result => result.AccessTokenType).Returns("type");
            mockAuthenticationResult.SetupGet(result => result.ExpiresOn).Returns(DateTimeOffset.UtcNow);

            var mockAuthenticationContextWrapper = new MockAuthenticationContextWrapper();

            mockAuthenticationContextWrapper.Setup(wrapper => wrapper.AcquireTokenSilentAsync(
                It.Is<string>(resource => resource.Equals(AuthenticationTestBase.ServiceResourceId)),
                It.Is<ClientCredential>(credential => credential.ClientId.Equals(AuthenticationTestBase.ClientId)),
                UserIdentifier.AnyUser)).Returns(Task.FromResult(mockAuthenticationResult.Object));

            var authenticationProvider = new AdalAuthenticationProvider(
                AuthenticationTestBase.ClientId,
                clientSecret,
                AuthenticationTestBase.ReturnUrl,
                mockAuthenticationContextWrapper.Object);

            await this.AuthenticateUserAsync(
                authenticationProvider,
                mockAuthenticationResult.Object);
        }

        [TestMethod]
        [ExpectedException(typeof(ServiceException))]
        public async Task AuthenticateUserAsync_ReturnUrlRequired()
        {
            var mockAuthenticationContextWrapper = new MockAuthenticationContextWrapper();
            mockAuthenticationContextWrapper.Setup(wrapper => wrapper.AcquireTokenSilentAsync(
                It.Is<string>(resource => resource.Equals(AuthenticationTestBase.ServiceResourceId)),
                It.Is<string>(clientId => clientId.Equals(AuthenticationTestBase.ClientId)),
                UserIdentifier.AnyUser)).Throws(new Exception());

            var authenticationProvider = new AdalAuthenticationProvider(
                AuthenticationTestBase.ClientId,
                null,
                mockAuthenticationContextWrapper.Object);

            try
            {
                await authenticationProvider.AuthenticateUserAsync(AuthenticationTestBase.ServiceResourceId);
            }
            catch (ServiceException exception)
            {
                Assert.IsNotNull(exception.Error, "Error not set in exception.");
                Assert.IsTrue(exception.IsMatch(OAuthConstants.ErrorCodes.AuthenticationFailure), "Unexpected error code returned.");
                Assert.AreEqual("The user could not be silently authenticated and return URL is required to prompt the user for authentication.",
                    exception.Error.Message,
                    "Unexpected error message returned.");
                Assert.IsNull(exception.InnerException, "Unexpected inner exception.");

                throw;
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ServiceException))]
        public async Task AuthenticateUserAsync_ServiceResourceIdRequired()
        {
            var authenticationProvider = new AdalAuthenticationProvider(
                AuthenticationTestBase.ClientId,
                AuthenticationTestBase.ReturnUrl);

            try
            {
                await authenticationProvider.AuthenticateUserAsync(null);
            }
            catch (ServiceException exception)
            {
                Assert.IsNotNull(exception.Error, "Error not set in exception.");
                Assert.IsTrue(exception.IsMatch(OAuthConstants.ErrorCodes.AuthenticationFailure), "Unexpected error code returned.");
                Assert.AreEqual("Service resource ID is required to authenticate a user with AuthenticateUserAsync.",
                    exception.Error.Message,
                    "Unexpected error message returned.");
                Assert.IsNull(exception.InnerException, "Unexpected inner exception.");

                throw;
            }
        }

        [TestMethod]
        public async Task AuthenticateUserAsync_ClientCertificate()
        {
            var clientCertificate = new X509Certificate2(@"Certs\testwebapplication.pfx", "password");
            var userId = "user id";

            var mockAuthenticationResult = new MockAuthenticationResult();
            mockAuthenticationResult.SetupGet(result => result.AccessToken).Returns("token");
            mockAuthenticationResult.SetupGet(result => result.AccessTokenType).Returns("type");
            mockAuthenticationResult.SetupGet(result => result.ExpiresOn).Returns(DateTimeOffset.UtcNow);
            
            var mockUserInfo = new Mock<IUserInfo>();
            mockUserInfo.SetupGet(userInfo => userInfo.UniqueId).Returns(userId);
            mockAuthenticationResult.SetupGet(result => result.UserInfo).Returns(mockUserInfo.Object);

            var mockAuthenticationContextWrapper = new MockAuthenticationContextWrapper();

            mockAuthenticationContextWrapper.Setup(wrapper => wrapper.AcquireTokenByAuthorizationCodeAsync(
                It.Is<string>(code => code.Equals(OAuthConstants.CodeKeyName)),
                It.Is<Uri>(returnUri => returnUri.ToString().Equals(AuthenticationTestBase.ReturnUrl)),
                It.Is<ClientAssertionCertificate>(certificate =>
                    certificate.Certificate == clientCertificate &&
                    certificate.ClientId.Equals(AuthenticationTestBase.ClientId)),
                It.Is<string>(resource => resource.Equals(ServiceResourceId))))
                .Returns(Task.FromResult(mockAuthenticationResult.Object));

            var webAuthenticationUi = new MockWebAuthenticationUi(
                new Dictionary<string, string>
                {
                    { OAuthConstants.CodeKeyName, OAuthConstants.CodeKeyName }
                });

            var authenticationProvider = new AdalAuthenticationProvider(
                AuthenticationTestBase.ClientId,
                clientCertificate,
                AuthenticationTestBase.ReturnUrl,
                mockAuthenticationContextWrapper.Object)
            {
                webAuthenticationUi = webAuthenticationUi.Object,
            };
            
            await this.AuthenticateUserAsync(
                authenticationProvider,
                mockAuthenticationResult.Object,
                userId);
        }

        [TestMethod]
        public async Task AuthenticateUserAsync_ClientCredential()
        {
            var clientSecret = "clientSecret";
            var userId = "user ID";

            var mockAuthenticationResult = new MockAuthenticationResult();
            mockAuthenticationResult.SetupGet(result => result.AccessToken).Returns("token");
            mockAuthenticationResult.SetupGet(result => result.AccessTokenType).Returns("type");
            mockAuthenticationResult.SetupGet(result => result.ExpiresOn).Returns(DateTimeOffset.UtcNow);

            var mockUserInfo = new Mock<IUserInfo>();
            mockUserInfo.SetupGet(userInfo => userInfo.UniqueId).Returns(userId);
            mockAuthenticationResult.SetupGet(result => result.UserInfo).Returns(mockUserInfo.Object);

            var mockAuthenticationContextWrapper = new MockAuthenticationContextWrapper();

            mockAuthenticationContextWrapper.Setup(wrapper => wrapper.AcquireTokenSilentAsync(
                It.Is<string>(resource => resource.Equals(AuthenticationTestBase.ServiceResourceId)),
                It.Is<string>(clientId => clientId.Equals(AuthenticationTestBase.ClientId)),
                UserIdentifier.AnyUser)).Throws(new Exception());

            mockAuthenticationContextWrapper.Setup(wrapper => wrapper.AcquireTokenByAuthorizationCodeAsync(
                It.Is<string>(code => code.Equals(OAuthConstants.CodeKeyName)),
                It.Is<Uri>(returnUri => returnUri.ToString().Equals(AuthenticationTestBase.ReturnUrl)),
                It.Is<ClientCredential>(credential => credential.ClientId.Equals(AuthenticationTestBase.ClientId)),
                It.Is<string>(resource => resource.Equals(AuthenticationTestBase.ServiceResourceId))))
                .Returns(Task.FromResult(mockAuthenticationResult.Object));

            var webAuthenticationUi = new MockWebAuthenticationUi(
                new Dictionary<string, string>
                {
                    { OAuthConstants.CodeKeyName, OAuthConstants.CodeKeyName }
                });

            var authenticationProvider = new AdalAuthenticationProvider(
                AuthenticationTestBase.ClientId,
                clientSecret,
                AuthenticationTestBase.ReturnUrl,
                mockAuthenticationContextWrapper.Object)
            {
                webAuthenticationUi = webAuthenticationUi.Object,
            };

            await this.AuthenticateUserAsync(
                authenticationProvider,
                mockAuthenticationResult.Object,
                userId);
        }

        [TestMethod]
        [ExpectedException(typeof(ServiceException))]
        public async Task AuthenticateUserAsync_AuthenticationError()
        {
            var innerException = new Exception();

            var mockAuthenticationContextWrapper = new MockAuthenticationContextWrapper();
            mockAuthenticationContextWrapper.Setup(wrapper => wrapper.AcquireTokenSilentAsync(
                It.Is<string>(resource => resource.Equals(AuthenticationTestBase.ServiceResourceId)),
                It.Is<string>(clientId => clientId.Equals(AuthenticationTestBase.ClientId)),
                UserIdentifier.AnyUser)).Throws(new Exception());

            mockAuthenticationContextWrapper.Setup(wrapper => wrapper.AcquireToken(
                It.Is<string>(resource => resource.Equals(AuthenticationTestBase.ServiceResourceId)),
                It.Is<string>(clientId => clientId.Equals(AuthenticationTestBase.ClientId)),
                It.Is<Uri>(returnUri => returnUri.ToString().Equals(AuthenticationTestBase.ReturnUrl)),
                PromptBehavior.Auto,
                UserIdentifier.AnyUser)).Throws(innerException);

            var authenticationProvider = new AdalAuthenticationProvider(
                AuthenticationTestBase.ClientId,
                AuthenticationTestBase.ReturnUrl,
                mockAuthenticationContextWrapper.Object);

            try
            {
                await this.AuthenticateUserAsync(authenticationProvider, null);
            }
            catch (ServiceException exception)
            {
                Assert.IsNotNull(exception.Error, "Error not set in exception.");
                Assert.IsTrue(exception.IsMatch(OAuthConstants.ErrorCodes.AuthenticationFailure), "Unexpected error code returned.");
                Assert.AreEqual("An error occurred during Azure Active Directory authentication.",
                    exception.Error.Message,
                    "Unexpected error message returned.");
                Assert.AreEqual(innerException, exception.InnerException, "Unexpected inner exception.");

                throw;
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ServiceException))]
        public async Task AuthenticateUserAsync_NullAuthenticationResult()
        {
            var mockAuthenticationContextWrapper = new MockAuthenticationContextWrapper();
            mockAuthenticationContextWrapper.Setup(wrapper => wrapper.AcquireTokenSilentAsync(
                It.Is<string>(resource => resource.Equals(ServiceResourceId)),
                It.Is<string>(clientId => clientId.Equals(AuthenticationTestBase.ClientId)),
                UserIdentifier.AnyUser)).Throws(new Exception());

            mockAuthenticationContextWrapper.Setup(wrapper => wrapper.AcquireToken(
                It.Is<string>(resource => resource.Equals(ServiceResourceId)),
                It.Is<string>(clientId => clientId.Equals(AuthenticationTestBase.ClientId)),
                It.Is<Uri>(returnUri => returnUri.ToString().Equals(AuthenticationTestBase.ReturnUrl)),
                PromptBehavior.Auto,
                UserIdentifier.AnyUser)).Returns((IAuthenticationResult)null);

            var authenticationProvider = new AdalAuthenticationProvider(
                AuthenticationTestBase.ClientId,
                AuthenticationTestBase.ReturnUrl,
                mockAuthenticationContextWrapper.Object);

            try
            {
                await this.AuthenticateUserAsync(authenticationProvider, null);
            }
            catch (ServiceException exception)
            {
                Assert.IsNotNull(exception.Error, "Error not set in exception.");
                Assert.IsTrue(exception.IsMatch(OAuthConstants.ErrorCodes.AuthenticationFailure), "Unexpected error code returned.");
                Assert.AreEqual(
                    "An error occurred during Azure Active Directory authentication.",
                    exception.Error.Message,
                    "Unexpected error message returned.");

                throw;
            }
        }

        [TestMethod]
        public async Task AuthenticateUserWithAuthorizationCodeAsync_ClientCertificate()
        {
            var authorizationCode = "code";
            var clientCertificate = new X509Certificate2(@"Certs\testwebapplication.pfx", "password");

            var mockAuthenticationResult = new MockAuthenticationResult();
            mockAuthenticationResult.SetupGet(result => result.AccessToken).Returns("token");
            mockAuthenticationResult.SetupGet(result => result.AccessTokenType).Returns("type");
            mockAuthenticationResult.SetupGet(result => result.ExpiresOn).Returns(DateTimeOffset.UtcNow);

            var mockAuthenticationContextWrapper = new MockAuthenticationContextWrapper();
            mockAuthenticationContextWrapper.Setup(wrapper => wrapper.AcquireTokenByAuthorizationCodeAsync(
                It.Is<string>(code => code.Equals(authorizationCode)),
                It.Is<Uri>(returnUri => returnUri == new Uri(AuthenticationTestBase.ReturnUrl)),
                It.Is<ClientAssertionCertificate>(certificate =>
                    certificate.ClientId.Equals(AuthenticationTestBase.ClientId) &&
                    certificate.Certificate == clientCertificate),
                It.Is<string>(resource => resource.Equals(AuthenticationTestBase.ServiceResourceId))))
                .Returns(Task.FromResult(mockAuthenticationResult.Object));

            var authenticationProvider = new AdalAuthenticationProvider(
                AuthenticationTestBase.ClientId,
                clientCertificate,
                AuthenticationTestBase.ReturnUrl,
                mockAuthenticationContextWrapper.Object);

            await this.AuthenticateUserWithAuthorizationCodeAsync(
                authorizationCode,
                authenticationProvider,
                mockAuthenticationResult.Object,
                true);
        }

        [TestMethod]
        public async Task AuthenticateUserWithAuthorizationCodeAsync_ClientCredential()
        {
            await this.AuthenticateUserWithAuthorizationCodeAsync_ClientCredential(false);
        }

        [TestMethod]
        public async Task AuthenticateUserWithAuthorizationCodeAsync_ClientCredential_ServiceResourceId()
        {
            await this.AuthenticateUserWithAuthorizationCodeAsync_ClientCredential(true);
        }
        
        public async Task AuthenticateUserWithAuthorizationCodeAsync_ClientCredential(bool includeServiceResourceId)
        {
            var authorizationCode = "code";
            var clientSecret = "client secret";

            var mockAuthenticationResult = new MockAuthenticationResult();
            mockAuthenticationResult.SetupGet(result => result.AccessToken).Returns("token");
            mockAuthenticationResult.SetupGet(result => result.AccessTokenType).Returns("type");
            mockAuthenticationResult.SetupGet(result => result.ExpiresOn).Returns(DateTimeOffset.UtcNow);

            var mockAuthenticationContextWrapper = new MockAuthenticationContextWrapper();

            if (includeServiceResourceId)
            {
                mockAuthenticationContextWrapper.Setup(wrapper => wrapper.AcquireTokenByAuthorizationCodeAsync(
                    It.Is<string>(token => token.Equals(authorizationCode)),
                    It.Is<Uri>(returnUri => returnUri == new Uri(AuthenticationTestBase.ReturnUrl)),
                    It.Is<ClientCredential>(credential => credential.ClientId.Equals(AuthenticationTestBase.ClientId)),
                    It.Is<string>(resource => resource.Equals(AuthenticationTestBase.ServiceResourceId))))
                    .Returns(Task.FromResult(mockAuthenticationResult.Object));
            }
            else
            {
                mockAuthenticationContextWrapper.Setup(wrapper => wrapper.AcquireTokenByAuthorizationCodeAsync(
                    It.Is<string>(token => token.Equals(authorizationCode)),
                    It.Is<Uri>(returnUri => returnUri == new Uri(AuthenticationTestBase.ReturnUrl)),
                    It.Is<ClientCredential>(credential => credential.ClientId.Equals(AuthenticationTestBase.ClientId)),
                    null))
                    .Returns(Task.FromResult(mockAuthenticationResult.Object));
            }

            var authenticationProvider = new AdalAuthenticationProvider(
                AuthenticationTestBase.ClientId,
                clientSecret,
                AuthenticationTestBase.ReturnUrl,
                mockAuthenticationContextWrapper.Object);

            await this.AuthenticateUserWithAuthorizationCodeAsync(
                authorizationCode,
                authenticationProvider,
                mockAuthenticationResult.Object,
                includeServiceResourceId);
        }

        [TestMethod]
        [ExpectedException(typeof(ServiceException))]
        public async Task AuthenticateUserWithAuthorizationCodeAsync_AuthenticationError()
        {
            var authorizationCode = "code";
            var clientSecret = "client secret";

            var mockAuthenticationResult = new MockAuthenticationResult();
            mockAuthenticationResult.SetupGet(result => result.AccessToken).Returns("token");
            mockAuthenticationResult.SetupGet(result => result.AccessTokenType).Returns("type");
            mockAuthenticationResult.SetupGet(result => result.ExpiresOn).Returns(DateTimeOffset.UtcNow);

            var mockAuthenticationContextWrapper = new MockAuthenticationContextWrapper();
            mockAuthenticationContextWrapper.Setup(wrapper => wrapper.AcquireTokenByAuthorizationCodeAsync(
                It.Is<string>(token => token.Equals(authorizationCode)),
                It.Is<Uri>(returnUri => returnUri == new Uri(AuthenticationTestBase.ReturnUrl)),
                It.Is<ClientCredential>(credential => credential.ClientId.Equals(AuthenticationTestBase.ClientId)),
                It.Is<string>(resource => resource.Equals(AuthenticationTestBase.ServiceResourceId))))
                .Throws(new Exception());

            var authenticationProvider = new AdalAuthenticationProvider(
                AuthenticationTestBase.ClientId,
                clientSecret,
                AuthenticationTestBase.ReturnUrl,
                mockAuthenticationContextWrapper.Object);

            try
            {
                await this.AuthenticateUserWithAuthorizationCodeAsync(
                    authorizationCode,
                    authenticationProvider,
                    mockAuthenticationResult.Object,
                    true);
            }
            catch (ServiceException exception)
            {
                Assert.IsNotNull(exception.Error, "Error not set in exception.");
                Assert.IsTrue(exception.IsMatch(OAuthConstants.ErrorCodes.AuthenticationFailure), "Unexpected error code returned.");
                Assert.AreEqual(
                    "An error occurred during Azure Active Directory authentication.",
                    exception.Error.Message,
                    "Unexpected error message returned.");

                throw;
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ServiceException))]
        public async Task AuthenticateUserWithAuthorizationCodeAsync_AuthorizationCodeRequired()
        {
            var clientCertificate = new X509Certificate2(@"Certs\testwebapplication.pfx", "password");

            var authenticationProvider = new AdalAuthenticationProvider(
                AuthenticationTestBase.ClientId,
                clientCertificate,
                AuthenticationTestBase.ReturnUrl);

            try
            {
                await this.AuthenticateUserWithAuthorizationCodeAsync(
                    null,
                    authenticationProvider,
                    null,
                    false);
            }
            catch (ServiceException exception)
            {
                Assert.IsNotNull(exception.Error, "Error not set in exception.");
                Assert.IsTrue(exception.IsMatch(OAuthConstants.ErrorCodes.AuthenticationFailure), "Unexpected error code returned.");
                Assert.AreEqual(
                    "Authorization code is required to authenticate a user with an authorization code.",
                    exception.Error.Message,
                    "Unexpected error message returned.");

                throw;
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ServiceException))]
        public async Task AuthenticateUserWithAuthorizationCodeAsync_CertificateOrSecretRequired()
        {
            var authenticationProvider = new AdalAuthenticationProvider(
                AuthenticationTestBase.ClientId,
                AuthenticationTestBase.ReturnUrl);

            try
            {
                await this.AuthenticateUserWithAuthorizationCodeAsync(
                    "code",
                    authenticationProvider,
                    null,
                    false);
            }
            catch (ServiceException exception)
            {
                Assert.IsNotNull(exception.Error, "Error not set in exception.");
                Assert.IsTrue(exception.IsMatch(OAuthConstants.ErrorCodes.AuthenticationFailure), "Unexpected error code returned.");
                Assert.AreEqual(
                    "Client certificate or client secret is required to authenticate a user with an authorization code.",
                    exception.Error.Message,
                    "Unexpected error message returned.");

                throw;
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ServiceException))]
        public async Task AuthenticateUserWithAuthorizationCodeAsync_NullAuthenticationResult()
        {
            var authorizationCode = "code";
            var clientSecret = "client secret";

            var mockAuthenticationContextWrapper = new MockAuthenticationContextWrapper();
            mockAuthenticationContextWrapper.Setup(wrapper => wrapper.AcquireTokenByAuthorizationCodeAsync(
                It.Is<string>(token => token.Equals(authorizationCode)),
                It.Is<Uri>(returnUri => returnUri == new Uri(AuthenticationTestBase.ReturnUrl)),
                It.Is<ClientCredential>(credential => credential.ClientId.Equals(AuthenticationTestBase.ClientId)),
                It.Is<string>(resource => resource.Equals(AuthenticationTestBase.ServiceResourceId))))
                .Returns(Task.FromResult<IAuthenticationResult>(null));

            var authenticationProvider = new AdalAuthenticationProvider(
                AuthenticationTestBase.ClientId,
                clientSecret,
                AuthenticationTestBase.ReturnUrl,
                mockAuthenticationContextWrapper.Object);

            try
            {
                await this.AuthenticateUserWithAuthorizationCodeAsync(
                authorizationCode,
                authenticationProvider,
                null,
                true);
            }
            catch (ServiceException exception)
            {
                Assert.IsNotNull(exception.Error, "Error not set in exception.");
                Assert.IsTrue(exception.IsMatch(OAuthConstants.ErrorCodes.AuthenticationFailure), "Unexpected error code returned.");
                Assert.AreEqual(
                    "An error occurred during Azure Active Directory authentication.",
                    exception.Error.Message,
                    "Unexpected error message returned.");

                throw;
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ServiceException))]
        public async Task AuthenticateUserWithAuthorizationCodeAsync_ReturnUrlRequired()
        {
            var authenticationProvider = new AdalAuthenticationProvider(
                AuthenticationTestBase.ClientId,
                /* returnUrl */ null);

            try
            {
                await this.AuthenticateUserWithAuthorizationCodeAsync(
                    "code",
                    authenticationProvider,
                    null,
                    false);
            }
            catch (ServiceException exception)
            {
                Assert.IsNotNull(exception.Error, "Error not set in exception.");
                Assert.IsTrue(exception.IsMatch(OAuthConstants.ErrorCodes.AuthenticationFailure), "Unexpected error code returned.");
                Assert.AreEqual(
                    "Return URL is required to authenticate a user with an authorization code.",
                    exception.Error.Message,
                    "Unexpected error message returned.");

                throw;
            }
        }

        [TestMethod]
        public async Task AuthenticateUserWithRefreshTokenAsync()
        {
            await this.AuthenticateUserWithRefreshTokenAsync(false);
        }

        [TestMethod]
        public async Task AuthenticateUserWithRefreshTokenAsync_ServiceResourceId()
        {
            await this.AuthenticateUserWithRefreshTokenAsync(true);
        }

        public async Task AuthenticateUserWithRefreshTokenAsync(bool includeServiceResourceId)
        {
            string refreshToken = "refresh";

            var mockAuthenticationResult = new MockAuthenticationResult();
            mockAuthenticationResult.SetupGet(result => result.AccessToken).Returns("token");
            mockAuthenticationResult.SetupGet(result => result.AccessTokenType).Returns("type");
            mockAuthenticationResult.SetupGet(result => result.ExpiresOn).Returns(DateTimeOffset.UtcNow);

            var mockAuthenticationContextWrapper = new MockAuthenticationContextWrapper();

            if (includeServiceResourceId)
            {
                mockAuthenticationContextWrapper.Setup(wrapper => wrapper.AcquireTokenByRefreshTokenAsync(
                    It.Is<string>(token => token.Equals(refreshToken)),
                    It.Is<string>(clientId => clientId.Equals(AuthenticationTestBase.ClientId)),
                    It.Is<string>(resource => resource.Equals(AuthenticationTestBase.ServiceResourceId))))
                    .Returns(Task.FromResult(mockAuthenticationResult.Object));
            }
            else
            {
                mockAuthenticationContextWrapper.Setup(wrapper => wrapper.AcquireTokenByRefreshTokenAsync(
                    It.Is<string>(token => token.Equals(refreshToken)),
                    It.Is<string>(clientId => clientId.Equals(AuthenticationTestBase.ClientId)),
                    null))
                    .Returns(Task.FromResult(mockAuthenticationResult.Object));
            }

            var authenticationProvider = new AdalAuthenticationProvider(
                AuthenticationTestBase.ClientId,
                AuthenticationTestBase.ReturnUrl,
                mockAuthenticationContextWrapper.Object);

            await this.AuthenticateUserWithRefreshTokenAsync(
                refreshToken,
                authenticationProvider,
                mockAuthenticationResult.Object,
                includeServiceResourceId);
        }

        [TestMethod]
        public async Task AuthenticateUserWithRefreshTokenAsync_ClientCertificate()
        {
            string refreshToken = "refresh";

            var clientCertificate = new X509Certificate2(@"Certs\testwebapplication.pfx", "password");

            var mockAuthenticationResult = new MockAuthenticationResult();
            mockAuthenticationResult.SetupGet(result => result.AccessToken).Returns("token");
            mockAuthenticationResult.SetupGet(result => result.AccessTokenType).Returns("type");
            mockAuthenticationResult.SetupGet(result => result.ExpiresOn).Returns(DateTimeOffset.UtcNow);

            var mockAuthenticationContextWrapper = new MockAuthenticationContextWrapper();

            mockAuthenticationContextWrapper.Setup(wrapper => wrapper.AcquireTokenByRefreshTokenAsync(
                It.Is<string>(token => token.Equals(refreshToken)),
                It.Is<ClientAssertionCertificate>(certificate =>
                    certificate.ClientId.Equals(AuthenticationTestBase.ClientId) &&
                    certificate.Certificate == clientCertificate),
                It.Is<string>(resource => resource.Equals(AuthenticationTestBase.ServiceResourceId))))
                .Returns(Task.FromResult(mockAuthenticationResult.Object));

            var authenticationProvider = new AdalAuthenticationProvider(
                AuthenticationTestBase.ClientId,
                clientCertificate,
                AuthenticationTestBase.ReturnUrl,
                mockAuthenticationContextWrapper.Object);

            await this.AuthenticateUserWithRefreshTokenAsync(
                refreshToken,
                authenticationProvider,
                mockAuthenticationResult.Object,
                true);
        }

        [TestMethod]
        public async Task AuthenticateUserWithRefreshTokenAsync_ClientCredential()
        {
            string refreshToken = "refresh";

            var clientSecret = "client secret";

            var mockAuthenticationResult = new MockAuthenticationResult();
            mockAuthenticationResult.SetupGet(result => result.AccessToken).Returns("token");
            mockAuthenticationResult.SetupGet(result => result.AccessTokenType).Returns("type");
            mockAuthenticationResult.SetupGet(result => result.ExpiresOn).Returns(DateTimeOffset.UtcNow);

            var mockAuthenticationContextWrapper = new MockAuthenticationContextWrapper();

            mockAuthenticationContextWrapper.Setup(wrapper => wrapper.AcquireTokenByRefreshTokenAsync(
                It.Is<string>(token => token.Equals(refreshToken)),
                It.Is<ClientCredential>(credential => credential.ClientId.Equals(AuthenticationTestBase.ClientId)),
                It.Is<string>(resource => resource.Equals(AuthenticationTestBase.ServiceResourceId))))
                .Returns(Task.FromResult(mockAuthenticationResult.Object));

            var authenticationProvider = new AdalAuthenticationProvider(
                AuthenticationTestBase.ClientId,
                clientSecret,
                AuthenticationTestBase.ReturnUrl,
                mockAuthenticationContextWrapper.Object);

            await this.AuthenticateUserWithRefreshTokenAsync(
                refreshToken,
                authenticationProvider,
                mockAuthenticationResult.Object,
                true);
        }

        [TestMethod]
        [ExpectedException(typeof(ServiceException))]
        public async Task AuthenticateUserWithRefreshTokenAsync_AuthenticationException()
        {
            string refreshToken = "refresh";

            var mockAuthenticationContextWrapper = new MockAuthenticationContextWrapper();

            mockAuthenticationContextWrapper.Setup(wrapper => wrapper.AcquireTokenByRefreshTokenAsync(
                It.Is<string>(token => token.Equals(refreshToken)),
                It.Is<string>(clientId => clientId.Equals(AuthenticationTestBase.ClientId)),
                It.Is<string>(resource => resource.Equals(AuthenticationTestBase.ServiceResourceId))))
                .Throws(new Exception());

            var authenticationProvider = new AdalAuthenticationProvider(
                AuthenticationTestBase.ClientId,
                AuthenticationTestBase.ReturnUrl,
                mockAuthenticationContextWrapper.Object);

            try
            {
                await this.AuthenticateUserWithRefreshTokenAsync(
                    refreshToken,
                    authenticationProvider,
                    null,
                    true);
            }
            catch (ServiceException exception)
            {
                Assert.IsNotNull(exception.Error, "Error not set in exception.");
                Assert.IsTrue(exception.IsMatch(OAuthConstants.ErrorCodes.AuthenticationFailure), "Unexpected error code returned.");
                Assert.AreEqual(
                    "An error occurred during Azure Active Directory authentication.",
                    exception.Error.Message,
                    "Unexpected error message returned.");

                throw;
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ServiceException))]
        public async Task AuthenticateUserWithRefreshTokenAsync_NullAuthenticationResult()
        {
            string refreshToken = "refresh";

            var mockAuthenticationContextWrapper = new MockAuthenticationContextWrapper();

            mockAuthenticationContextWrapper.Setup(wrapper => wrapper.AcquireTokenByRefreshTokenAsync(
                It.Is<string>(token => token.Equals(refreshToken)),
                It.Is<string>(clientId => clientId.Equals(AuthenticationTestBase.ClientId)),
                It.Is<string>(resource => resource.Equals(AuthenticationTestBase.ServiceResourceId))))
                .Returns(Task.FromResult<IAuthenticationResult>(null));

            var authenticationProvider = new AdalAuthenticationProvider(
                AuthenticationTestBase.ClientId,
                AuthenticationTestBase.ReturnUrl,
                mockAuthenticationContextWrapper.Object);

            try
            {
                await this.AuthenticateUserWithRefreshTokenAsync(
                    refreshToken,
                    authenticationProvider,
                    null,
                    true);
            }
            catch (ServiceException exception)
            {
                Assert.IsNotNull(exception.Error, "Error not set in exception.");
                Assert.IsTrue(exception.IsMatch(OAuthConstants.ErrorCodes.AuthenticationFailure), "Unexpected error code returned.");
                Assert.AreEqual(
                    "An error occurred during Azure Active Directory authentication.",
                    exception.Error.Message,
                    "Unexpected error message returned.");

                throw;
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ServiceException))]
        public async Task AuthenticateUserWithRefreshTokenAsync_RefreshTokenRequired()
        {
            var clientSecret = "client secret";
            var authenticationProvider = new AdalAuthenticationProvider(
                AuthenticationTestBase.ClientId,
                clientSecret,
                AuthenticationTestBase.ReturnUrl);

            try
            {
                await this.AuthenticateUserWithRefreshTokenAsync(
                    null,
                    authenticationProvider,
                    null,
                    false);
            }
            catch (ServiceException exception)
            {
                Assert.IsNotNull(exception.Error, "Error not set in exception.");
                Assert.IsTrue(exception.IsMatch(OAuthConstants.ErrorCodes.AuthenticationFailure), "Unexpected error code returned.");
                Assert.AreEqual(
                    "Refresh token is required to authenticate a user with a refresh token.",
                    exception.Error.Message,
                    "Unexpected error message returned.");

                throw;
            }
        }
        
        [TestMethod]
        public async Task SignOutAsync()
        {
            var accountSession = new AccountSession
            {
                AccessToken = "accessToken",
                ClientId = "12345",
            };

            var authenticationProvider = new AdalAuthenticationProvider(
                AuthenticationTestBase.ClientId,
                AuthenticationTestBase.ReturnUrl)
            {
                adalCredentialCache = this.credentialCache.Object,
                CurrentAccountSession = accountSession,
            };

            await authenticationProvider.SignOutAsync();

            /*this.httpProvider.Verify(
                provider => provider.SendAsync(
                    It.Is<HttpRequestMessage>(message => message.RequestUri.ToString().Equals(this.adalServiceInfo.SignOutUrl))),
                Times.Once);*/

            Assert.IsNull(authenticationProvider.CurrentAccountSession, "Current account session not cleared.");
            Assert.IsNull(authenticationProvider.currentServiceResourceId, "Current account session not cleared.");

            this.credentialCache.Verify(cache => cache.Clear(), Times.Once);
        }

        public async Task AuthenticateUserAsync(
            AdalAuthenticationProvider authenticationProvider,
            IAuthenticationResult authenticationResult,
            string userId = null)
        {
            await authenticationProvider.AuthenticateUserAsync(AuthenticationTestBase.ServiceResourceId, userId);
            
            Assert.AreEqual(authenticationResult.AccessToken, authenticationProvider.CurrentAccountSession.AccessToken, "Unexpected access token set.");
            Assert.AreEqual(authenticationResult.AccessTokenType, authenticationProvider.CurrentAccountSession.AccessTokenType, "Unexpected access token type set.");
            Assert.AreEqual(AuthenticationTestBase.ClientId, authenticationProvider.CurrentAccountSession.ClientId, "Unexpected client ID set.");
            Assert.AreEqual(authenticationResult.ExpiresOn, authenticationProvider.CurrentAccountSession.ExpiresOnUtc, "Unexpected expiration set.");
            Assert.AreEqual(userId, authenticationProvider.CurrentAccountSession.UserId, "Unexpected user ID set.");
        }

        public async Task AuthenticateUserWithAuthorizationCodeAsync(
            string refreshToken,
            AdalAuthenticationProvider authenticationProvider,
            IAuthenticationResult authenticationResult,
            bool includeServiceResourceId)
        {
            if (includeServiceResourceId)
            {
                await authenticationProvider.AuthenticateUserWithAuthorizationCodeAsync(refreshToken, AuthenticationTestBase.ServiceResourceId);
            }
            else
            {
                await authenticationProvider.AuthenticateUserWithAuthorizationCodeAsync(refreshToken);
            }

            Assert.AreEqual(authenticationResult.AccessToken, authenticationProvider.CurrentAccountSession.AccessToken, "Unexpected access token set.");
            Assert.AreEqual(authenticationResult.AccessTokenType, authenticationProvider.CurrentAccountSession.AccessTokenType, "Unexpected access token type set.");
            Assert.AreEqual(AuthenticationTestBase.ClientId, authenticationProvider.CurrentAccountSession.ClientId, "Unexpected client ID set.");
            Assert.AreEqual(authenticationResult.ExpiresOn, authenticationProvider.CurrentAccountSession.ExpiresOnUtc, "Unexpected expiration set.");
            Assert.IsNull(authenticationProvider.CurrentAccountSession.UserId, "Unexpected user ID set.");
        }

        public async Task AuthenticateUserWithRefreshTokenAsync(
            string refreshToken,
            AdalAuthenticationProvider authenticationProvider,
            IAuthenticationResult authenticationResult,
            bool includeServiceResourceId)
        {
            if (includeServiceResourceId)
            {
                await authenticationProvider.AuthenticateUserWithRefreshTokenAsync(refreshToken, AuthenticationTestBase.ServiceResourceId);
            }
            else
            {
                await authenticationProvider.AuthenticateUserWithRefreshTokenAsync(refreshToken);
            }

            Assert.AreEqual(authenticationResult.AccessToken, authenticationProvider.CurrentAccountSession.AccessToken, "Unexpected access token set.");
            Assert.AreEqual(authenticationResult.AccessTokenType, authenticationProvider.CurrentAccountSession.AccessTokenType, "Unexpected access token type set.");
            Assert.AreEqual(AuthenticationTestBase.ClientId, authenticationProvider.CurrentAccountSession.ClientId, "Unexpected client ID set.");
            Assert.AreEqual(authenticationResult.ExpiresOn, authenticationProvider.CurrentAccountSession.ExpiresOnUtc, "Unexpected expiration set.");
            Assert.IsNull(authenticationProvider.CurrentAccountSession.UserId, "Unexpected user ID set.");
        }
    }
}
