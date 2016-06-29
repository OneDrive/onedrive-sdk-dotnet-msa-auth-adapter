// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Test.OneDrive.Sdk.Authentication.Desktop
{
    using System;
    using System.Collections.Generic;
    using System.Net.Http;
    using System.Threading.Tasks;

    using Microsoft.Graph;
    using Microsoft.IdentityModel.Clients.ActiveDirectory;
    using Microsoft.OneDrive.Sdk.Authentication;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using Mocks;
    using Moq;

    [TestClass]
    public class DiscoveryServiceHelperTests : AuthenticationTestBase
    {
        [TestInitialize]
        public override void Setup()
        {
            base.Setup();
        }

        [TestMethod]
        public async Task DiscoverFilesEndpointInformationForUserAsync()
        {
            var businessServiceInfo = await this.AuthenticateWithDiscoveryServiceAsync();

            Assert.AreEqual(AuthenticationTestBase.ServiceEndpointUrl, businessServiceInfo.ServiceEndpointBaseUrl, "Unexpected base URL.");
            Assert.AreEqual(AuthenticationTestBase.ServiceResourceId, businessServiceInfo.ServiceResourceId, "Unexpected service resource ID.");
        }

        [TestMethod]
        [ExpectedException(typeof(ServiceException))]
        public async Task DiscoverFilesEndpointInformationForUserAsync_MyFilesCapabilityNotFound()
        {
            try
            {
                var businessServiceInfo = await this.AuthenticateWithDiscoveryServiceAsync(new DiscoveryServiceResponse());
            }
            catch (ServiceException exception)
            {
                Assert.IsNotNull(exception.Error, "Error not set in exception.");
                Assert.IsTrue(exception.IsMatch(OAuthConstants.ErrorCodes.AuthenticationFailure), "Unexpected error code returned.");
                Assert.AreEqual("MyFiles capability not found for the current user.",
                    exception.Error.Message,
                    "Unexpected error message returned.");
                Assert.IsNull(exception.InnerException, "Unexpected inner exception.");

                throw;
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ServiceException))]
        public async Task DiscoverFilesEndpointInformationForUserAsync_VersionNotFound()
        {
            try
            {
                var businessServiceInfo = await this.AuthenticateWithDiscoveryServiceAsync(
                    new DiscoveryServiceResponse
                    {
                        Value = new List<DiscoveryService>
                        {
                            new DiscoveryService { Capability = "MyFiles", ServiceApiVersion = "1.0" }
                        }
                    });
            }
            catch (ServiceException exception)
            {
                Assert.IsNotNull(exception.Error, "Error not set in exception.");
                Assert.IsTrue(exception.IsMatch(OAuthConstants.ErrorCodes.AuthenticationFailure), "Unexpected error code returned.");
                Assert.AreEqual("MyFiles capability with version v2.0 not found for the current user.",
                    exception.Error.Message,
                    "Unexpected error message returned.");
                Assert.IsNull(exception.InnerException, "Unexpected inner exception.");

                throw;
            }
        }

        [TestMethod]
        public async Task DiscoverFilesEndpointInformationForUserWithRefreshTokenAsync()
        {
            var businessServiceInfo = await this.AuthenticateWithDiscoveryServiceAsync(refreshToken: "refresh");

            Assert.AreEqual(AuthenticationTestBase.ServiceEndpointUrl, businessServiceInfo.ServiceEndpointBaseUrl, "Unexpected base URL.");
            Assert.AreEqual(AuthenticationTestBase.ServiceResourceId, businessServiceInfo.ServiceResourceId, "Unexpected service resource ID.");
        }

        public async Task<BusinessServiceInformation> AuthenticateWithDiscoveryServiceAsync(
            DiscoveryServiceResponse discoveryServiceResponse = null,
            string refreshToken = null)
        {
            bool refresh = refreshToken != null;

            var mockAuthenticationResult = new MockAuthenticationResult();
            mockAuthenticationResult.SetupGet(result => result.AccessToken).Returns("token");
            mockAuthenticationResult.SetupGet(result => result.AccessTokenType).Returns((string)null);
            mockAuthenticationResult.SetupGet(result => result.ExpiresOn).Returns(DateTimeOffset.UtcNow.AddHours(1));

            var mockAuthenticationContextWrapper = new MockAuthenticationContextWrapper();

            if (refresh)
            {
                mockAuthenticationContextWrapper.Setup(wrapper => wrapper.AcquireTokenByRefreshTokenAsync(
                    It.Is<string>(token => token.Equals(refreshToken)),
                    It.Is<string>(clientId => clientId.Equals(AuthenticationTestBase.ClientId)),
                    It.Is<string>(resource => resource.Equals(OAuthConstants.ActiveDirectoryDiscoveryResource))))
                    .Returns(Task.FromResult(mockAuthenticationResult.Object));
            }
            else
            {
                mockAuthenticationContextWrapper.Setup(wrapper => wrapper.AcquireTokenSilentAsync(
                    It.Is<string>(resource => resource.Equals(OAuthConstants.ActiveDirectoryDiscoveryResource)),
                    It.Is<string>(clientId => clientId.Equals(AuthenticationTestBase.ClientId)),
                    UserIdentifier.AnyUser))
                    .Returns(Task.FromResult(mockAuthenticationResult.Object));
            }

            var authenticationProvider = new AdalAuthenticationProvider(
                AuthenticationTestBase.ClientId,
                AuthenticationTestBase.ReturnUrl,
                mockAuthenticationContextWrapper.Object);

            var discoveryServiceHelper = new DiscoveryServiceHelper(authenticationProvider);

            if (discoveryServiceResponse == null)
            {
                discoveryServiceResponse = new DiscoveryServiceResponse
                {
                    Value = new List<DiscoveryService>
                    {
                        new DiscoveryService
                        {
                            Capability = "MyFiles",
                            ServiceApiVersion = "v2.0",
                            ServiceEndpointUri = AuthenticationTestBase.ServiceEndpointUrl,
                            ServiceResourceId = AuthenticationTestBase.ServiceResourceId,
                        }
                    }
                };
            }

            var requestBodyString = this.serializer.SerializeObject(discoveryServiceResponse);

            BusinessServiceInformation businessServiceInformation = null;

            using (var stringContent = new StringContent(requestBodyString))
            {
                this.httpResponseMessage.Content = stringContent;

                if (refresh)
                {
                    businessServiceInformation = await discoveryServiceHelper.DiscoverFilesEndpointInformationForUserWithRefreshTokenAsync(
                        refreshToken,
                        httpProvider: this.httpProvider.Object);
                }
                else
                {
                    businessServiceInformation = await discoveryServiceHelper.DiscoverFilesEndpointInformationForUserAsync(httpProvider: this.httpProvider.Object);
                }
            }

            return businessServiceInformation;
        }

        /*[TestMethod]
        public async Task AuthenticateAsync_AuthenticateWithoutDiscoveryService()
        {
            this.adalServiceInfo.ServiceResource = ServiceResourceId;
            this.adalServiceInfo.BaseUrl = "https://localhost";

            var mockAuthenticationResult = new MockAuthenticationResult();
            mockAuthenticationResult.SetupGet(result => result.AccessToken).Returns("token");
            mockAuthenticationResult.SetupGet(result => result.AccessTokenType).Returns("type");
            mockAuthenticationResult.SetupGet(result => result.ExpiresOn).Returns(DateTimeOffset.UtcNow);

            var mockAuthenticationContextWrapper = new MockAuthenticationContextWrapper();

            mockAuthenticationContextWrapper.Setup(wrapper => wrapper.AcquireTokenSilentAsync(
                It.Is<string>(resource => resource.Equals(ServiceResourceId)),
                It.Is<string>(clientId => clientId.Equals(this.adalServiceInfo.AppId)))).Throws(new Exception());

            mockAuthenticationContextWrapper.Setup(wrapper => wrapper.AcquireToken(
                It.Is<string>(resource => resource.Equals(ServiceResourceId)),
                It.Is<string>(clientId => clientId.Equals(this.adalServiceInfo.AppId)),
                It.Is<Uri>(returnUri => returnUri.ToString().Equals(this.adalServiceInfo.ReturnUrl)),
                PromptBehavior.Auto,
                UserIdentifier.AnyUser)).Returns(mockAuthenticationResult.Object);

            await this.AuthenticateAsync_AuthenticateWithoutDiscoveryService(
                mockAuthenticationContextWrapper.Object,
                mockAuthenticationResult.Object);
        }

        [TestMethod]
        public async Task AuthenticateAsync_AuthenticateWithRefreshToken()
        {
            string refreshToken = "refresh";

            this.authenticationProvider.CurrentAccountSession = new AccountSession { RefreshToken = refreshToken };
            
            var mockAuthenticationResult = new MockAuthenticationResult();
            mockAuthenticationResult.SetupGet(result => result.AccessToken).Returns("token");
            mockAuthenticationResult.SetupGet(result => result.AccessTokenType).Returns("type");
            mockAuthenticationResult.SetupGet(result => result.ExpiresOn).Returns(DateTimeOffset.UtcNow);

            var mockAuthenticationContextWrapper = new MockAuthenticationContextWrapper();

            mockAuthenticationContextWrapper.Setup(wrapper => wrapper.AcquireTokenByRefreshTokenAsync(
                It.Is<string>(token => token.Equals(refreshToken)),
                It.Is<string>(clientId => clientId.Equals(this.adalServiceInfo.AppId)),
                It.Is<string>(resource => resource.Equals(this.adalServiceInfo.ServiceResource)))).Returns(Task.FromResult(mockAuthenticationResult.Object));

            await this.AuthenticateAsync_AuthenticateWithoutDiscoveryService(
                mockAuthenticationContextWrapper.Object,
                mockAuthenticationResult.Object);
        }

        [TestMethod]
        public async Task AuthenticateAsync_AuthenticateWithRefreshToken_WithClientCertificate()
        {
            string refreshToken = "refresh";

            this.authenticationProvider.CurrentAccountSession = new AccountSession { RefreshToken = refreshToken };

            this.adalServiceInfo.ClientCertificate = new X509Certificate2(@"Certs\testwebapplication.pfx", "password");

            var mockAuthenticationResult = new MockAuthenticationResult();
            mockAuthenticationResult.SetupGet(result => result.AccessToken).Returns("token");
            mockAuthenticationResult.SetupGet(result => result.AccessTokenType).Returns("type");
            mockAuthenticationResult.SetupGet(result => result.ExpiresOn).Returns(DateTimeOffset.UtcNow);

            var mockAuthenticationContextWrapper = new MockAuthenticationContextWrapper();

            mockAuthenticationContextWrapper.Setup(wrapper => wrapper.AcquireTokenByRefreshTokenAsync(
                It.Is<string>(token => token.Equals(refreshToken)),
                It.Is<ClientAssertionCertificate>(certificate =>
                    certificate.ClientId.Equals(this.adalServiceInfo.AppId) &&
                    certificate.Certificate == this.adalServiceInfo.ClientCertificate),
                It.Is<string>(resource => resource.Equals(ServiceResourceId)))).Returns(Task.FromResult(mockAuthenticationResult.Object));

            await this.AuthenticateAsync_AuthenticateWithoutDiscoveryService(
                mockAuthenticationContextWrapper.Object,
                mockAuthenticationResult.Object);
        }

        [TestMethod]
        public async Task AuthenticateAsync_AuthenticateWithRefreshToken_WithClientCredential()
        {
            string refreshToken = "refresh";

            this.authenticationProvider.CurrentAccountSession = new AccountSession { RefreshToken = refreshToken };

            this.adalServiceInfo.ClientSecret = "clientSecret";

            var mockAuthenticationResult = new MockAuthenticationResult();
            mockAuthenticationResult.SetupGet(result => result.AccessToken).Returns("token");
            mockAuthenticationResult.SetupGet(result => result.AccessTokenType).Returns("type");
            mockAuthenticationResult.SetupGet(result => result.ExpiresOn).Returns(DateTimeOffset.UtcNow);

            var mockAuthenticationContextWrapper = new MockAuthenticationContextWrapper();
            
            mockAuthenticationContextWrapper.Setup(wrapper => wrapper.AcquireTokenByRefreshTokenAsync(
                It.Is<string>(token => token.Equals(refreshToken)),
                It.Is<ClientCredential>(credential => credential.ClientId.Equals(this.adalServiceInfo.AppId)),
                It.Is<string>(resource => resource.Equals(this.adalServiceInfo.ServiceResource)))).Returns(Task.FromResult(mockAuthenticationResult.Object));

            await this.AuthenticateAsync_AuthenticateWithoutDiscoveryService(
                mockAuthenticationContextWrapper.Object,
                mockAuthenticationResult.Object);
        }

        [TestMethod]
        [ExpectedException(typeof(OneDriveException))]
        public async Task AuthenticateAsync_AuthenticationError()
        {
            var innerException = new Exception();

            var mockAuthenticationContextWrapper = new MockAuthenticationContextWrapper();
            
            mockAuthenticationContextWrapper.Setup(wrapper => wrapper.AcquireTokenSilentAsync(
                It.Is<string>(resource => resource.Equals(ServiceResourceId)),
                It.Is<string>(clientId => clientId.Equals(this.adalServiceInfo.AppId)))).Throws(new Exception());

            mockAuthenticationContextWrapper.Setup(wrapper => wrapper.AcquireToken(
                It.Is<string>(resource => resource.Equals(ServiceResourceId)),
                It.Is<string>(clientId => clientId.Equals(this.adalServiceInfo.AppId)),
                It.Is<Uri>(returnUri => returnUri.ToString().Equals(this.adalServiceInfo.ReturnUrl)),
                PromptBehavior.Auto,
                UserIdentifier.AnyUser)).Throws(innerException);
            
            try
            {
                await this.AuthenticateWithDiscoveryService(mockAuthenticationContextWrapper);
            }
            catch (OneDriveException exception)
            {
                Assert.IsNotNull(exception.Error, "Error not set in exception.");
                Assert.AreEqual(OneDriveErrorCode.AuthenticationFailure.ToString(), exception.Error.Code, "Unexpected error code returned.");
                Assert.AreEqual("An error occurred during Azure Active Directory authentication.",
                    exception.Error.Message,
                    "Unexpected error message returned.");
                Assert.AreEqual(innerException, exception.InnerException, "Unexpected inner exception.");

                throw;
            }
        }

        [TestMethod]
        public async Task AuthenticateAsync_CachedCurrentAccountSession()
        {
            var cachedAccountSession = new AccountSession
            {
                AccessToken = "token",
                ExpiresOnUtc = DateTimeOffset.UtcNow.AddMinutes(10),
            };

            this.authenticationProvider.CurrentAccountSession = cachedAccountSession;

            var accountSession = await this.authenticationProvider.AuthenticateAsync();

            Assert.IsNotNull(accountSession, "No account session returned.");
            Assert.AreEqual(cachedAccountSession.AccessToken, accountSession.AccessToken, "Unexpected access token returned.");
            Assert.AreEqual(cachedAccountSession.ExpiresOnUtc, accountSession.ExpiresOnUtc, "Unexpected expiration returned.");
        }

        [TestMethod]
        public async Task AuthenticateAsync_CachedCurrentAccountSessionExpiring()
        {
            var cachedAccountSession = new AccountSession
            {
                AccessToken = "expiredToken",
                ExpiresOnUtc = DateTimeOffset.UtcNow,
            };

            this.authenticationProvider.CurrentAccountSession = cachedAccountSession;
            
            var mockAuthenticationResult = new MockAuthenticationResult();
            mockAuthenticationResult.SetupGet(result => result.AccessToken).Returns("token");
            mockAuthenticationResult.SetupGet(result => result.AccessTokenType).Returns("type");
            mockAuthenticationResult.SetupGet(result => result.ExpiresOn).Returns(DateTimeOffset.UtcNow.AddHours(1));

            var mockAuthenticationContextWrapper = new MockAuthenticationContextWrapper();
            mockAuthenticationContextWrapper.Setup(wrapper => wrapper.AcquireTokenSilentAsync(
                It.Is<string>(resource => resource.Equals(ServiceResourceId)),
                It.Is<string>(clientId => clientId.Equals(this.adalServiceInfo.AppId))))
                .Returns(Task.FromResult(mockAuthenticationResult.Object));

            await this.AuthenticateAsync_AuthenticateWithoutDiscoveryService(
                mockAuthenticationContextWrapper.Object,
                mockAuthenticationResult.Object);
        }

        [TestMethod]
        [ExpectedException(typeof(OneDriveException))]
        public async Task AuthenticateAsync_DiscoveryServiceMyFilesCapabilityNotFound()
        {
            var mockAuthenticationContextWrapper = new MockAuthenticationContextWrapper();
            try
            {
                await this.AuthenticateWithDiscoveryService(
                    mockAuthenticationContextWrapper,
                    new DiscoveryServiceResponse
                    {
                        Value = new List<DiscoveryService>
                        {
                            new DiscoveryService
                            {
                                Capability = "Mail",
                                ServiceApiVersion = "v2.0"
                            }
                        }
                    });
            }
            catch (OneDriveException exception)
            {
                Assert.IsNotNull(exception.Error, "Error not set in exception.");
                Assert.AreEqual(OneDriveErrorCode.MyFilesCapabilityNotFound.ToString(), exception.Error.Code, "Unexpected error code returned.");
                Assert.AreEqual(
                    string.Format(
                        "{0} capability with version {1} not found for the current user.",
                        Constants.Authentication.MyFilesCapability,
                        this.adalServiceInfo.OneDriveServiceEndpointVersion),
                    exception.Error.Message,
                    "Unexpected error message returned.");

                throw;
            }
        }

        [TestMethod]
        [ExpectedException(typeof(OneDriveException))]
        public async Task AuthenticateAsync_DiscoveryServiceMyFilesVersionNotFound()
        {
            var mockAuthenticationContextWrapper = new MockAuthenticationContextWrapper();
            try
            {
                await this.AuthenticateWithDiscoveryService(
                    mockAuthenticationContextWrapper,
                    new DiscoveryServiceResponse
                    {
                        Value = new List<DiscoveryService>
                        {
                            new DiscoveryService
                            {
                                Capability = Constants.Authentication.MyFilesCapability,
                                ServiceApiVersion = "v1.0"
                            }
                        }
                    });
            }
            catch (OneDriveException exception)
            {
                Assert.IsNotNull(exception.Error, "Error not set in exception.");
                Assert.AreEqual(OneDriveErrorCode.MyFilesCapabilityNotFound.ToString(), exception.Error.Code, "Unexpected error code returned.");
                Assert.AreEqual(
                    string.Format(
                        "{0} capability with version {1} not found for the current user.",
                        Constants.Authentication.MyFilesCapability,
                        this.adalServiceInfo.OneDriveServiceEndpointVersion),
                    exception.Error.Message,
                    "Unexpected error message returned.");

                throw;
            }
        }

        [TestMethod]
        [ExpectedException(typeof(OneDriveException))]
        public async Task AuthenticateAsync_DiscoveryServiceResponseValueNull()
        {
            var mockAuthenticationContextWrapper = new MockAuthenticationContextWrapper();
            try
            {
                await this.AuthenticateWithDiscoveryService(
                    mockAuthenticationContextWrapper,
                    new DiscoveryServiceResponse());
            }
            catch (OneDriveException exception)
            {
                Assert.IsNotNull(exception.Error, "Error not set in exception.");
                Assert.AreEqual(OneDriveErrorCode.MyFilesCapabilityNotFound.ToString(), exception.Error.Code, "Unexpected error code returned.");
                Assert.AreEqual(
                    "MyFiles capability not found for the current user.",
                    exception.Error.Message,
                    "Unexpected error message returned.");

                throw;
            }
        }

        [TestMethod]
        [ExpectedException(typeof(OneDriveException))]
        public async Task AuthenticateAsync_NullAuthenticationResult()
        {
            var mockAuthenticationContextWrapper = new MockAuthenticationContextWrapper();
            mockAuthenticationContextWrapper.Setup(wrapper => wrapper.AcquireTokenSilentAsync(
                It.Is<string>(resource => resource.Equals(ServiceResourceId)),
                It.Is<string>(clientId => clientId.Equals(this.adalServiceInfo.AppId)))).Throws(new Exception());

            mockAuthenticationContextWrapper.Setup(wrapper => wrapper.AcquireToken(
                It.Is<string>(resource => resource.Equals(ServiceResourceId)),
                It.Is<string>(clientId => clientId.Equals(this.adalServiceInfo.AppId)),
                It.Is<Uri>(returnUri => returnUri.ToString().Equals(this.adalServiceInfo.ReturnUrl)),
                PromptBehavior.Auto,
                UserIdentifier.AnyUser)).Returns((IAuthenticationResult)null);

            try
            {
                await this.AuthenticateWithDiscoveryService(mockAuthenticationContextWrapper);
            }
            catch (OneDriveException exception)
            {
                Assert.IsNotNull(exception.Error, "Error not set in exception.");
                Assert.AreEqual(OneDriveErrorCode.AuthenticationFailure.ToString(), exception.Error.Code, "Unexpected error code returned.");
                Assert.AreEqual(
                    "An error occurred during Azure Active Directory authentication.",
                    exception.Error.Message,
                    "Unexpected error message returned.");

                throw;
            }
        }

        [TestMethod]
        [ExpectedException(typeof(OneDriveException))]
        public void ServiceInfo_IncorrectCredentialCacheType()
        {
            this.adalServiceInfo.CredentialCache = new MockCredentialCache().Object;

            try
            {
                this.authenticationProvider.ServiceInfo = this.adalServiceInfo;
            }
            catch (OneDriveException exception)
            {
                Assert.IsNotNull(exception.Error, "Error not set in exception.");
                Assert.AreEqual(OneDriveErrorCode.AuthenticationFailure.ToString(), exception.Error.Code, "Unexpected error code returned.");
                Assert.AreEqual(
                    "Invalid credential cache type for authentication using ADAL.",
                    exception.Error.Message,
                    "Unexpected error message returned.");

                throw;
            }
        }

        [TestMethod]
        [ExpectedException(typeof(OneDriveException))]
        public void ServiceInfo_NullAuthenticationServiceUrl()
        {
            try
            {
                this.authenticationProvider.ServiceInfo = new ServiceInfo();
            }
            catch (OneDriveException exception)
            {
                Assert.IsNotNull(exception.Error, "Error not set in exception.");
                Assert.AreEqual(OneDriveErrorCode.AuthenticationFailure.ToString(), exception.Error.Code, "Unexpected error code returned.");
                Assert.AreEqual(
                    "Invalid service info for authentication.",
                    exception.Error.Message,
                    "Unexpected error message returned.");

                throw;
            }
        }

        [TestMethod]
        public void ServiceInfo_Set()
        {
            var newServiceInfo = new ServiceInfo { AuthenticationServiceUrl = "https://login.live.com/authenticate" };
            this.authenticationProvider.authenticationContextWrapper = null;
            this.authenticationProvider.ServiceInfo = newServiceInfo;

            Assert.AreEqual(newServiceInfo, this.authenticationProvider.ServiceInfo, "Service info not correctly initialized.");
            Assert.IsNotNull(this.authenticationProvider.authenticationContextWrapper, "Authentication context wrapper not correctly initialized.");
        }

        [TestMethod]
        [ExpectedException(typeof(OneDriveException))]
        public void ServiceInfo_SetNull()
        {
            try
            {
                this.authenticationProvider.ServiceInfo = null;
            }
            catch (OneDriveException exception)
            {
                Assert.IsNotNull(exception.Error, "Error not set in exception.");
                Assert.AreEqual(OneDriveErrorCode.AuthenticationFailure.ToString(), exception.Error.Code, "Unexpected error code returned.");
                Assert.AreEqual(
                    "Invalid service info for authentication.",
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
                CanSignOut = true,
                ClientId = "12345",
            };

            this.authenticationProvider.CurrentAccountSession = accountSession;

            await this.authenticationProvider.SignOutAsync();

            this.httpProvider.Verify(
                provider => provider.SendAsync(
                    It.Is<HttpRequestMessage>(message => message.RequestUri.ToString().Equals(this.adalServiceInfo.SignOutUrl))),
                Times.Once);

            Assert.IsNull(this.authenticationProvider.CurrentAccountSession, "Current account session not cleared.");

            this.credentialCache.Verify(cache => cache.OnDeleteFromCache(), Times.Once);
        }

        public async Task AuthenticateAsync_AuthenticateWithoutDiscoveryService(
            IAuthenticationContextWrapper authenticationContextWrapper,
            IAuthenticationResult authenticationResult)
        {
            this.adalServiceInfo.BaseUrl = "https://localhost";
            this.adalServiceInfo.ServiceResource = ServiceResourceId;

            this.authenticationProvider.authenticationContextWrapper = authenticationContextWrapper;

            var accountSession = await this.authenticationProvider.AuthenticateAsync();

            Assert.AreEqual(accountSession, this.authenticationProvider.CurrentAccountSession, "Account session not cached correctly.");
            Assert.AreEqual(authenticationResult.AccessToken, accountSession.AccessToken, "Unexpected access token set.");
            Assert.AreEqual(authenticationResult.AccessTokenType, accountSession.AccessTokenType, "Unexpected access token type set.");
            Assert.AreEqual(AccountType.ActiveDirectory, accountSession.AccountType, "Unexpected account type set.");
            Assert.IsTrue(accountSession.CanSignOut, "CanSignOut set to false.");
            Assert.AreEqual(this.adalServiceInfo.AppId, accountSession.ClientId, "Unexpected client ID set.");
            Assert.AreEqual(authenticationResult.ExpiresOn, accountSession.ExpiresOnUtc, "Unexpected expiration set.");
            Assert.IsNull(accountSession.UserId, "Unexpected user ID set.");
        }

        public async Task AuthenticateAsync_AuthenticateWithDiscoveryService(
            MockAuthenticationContextWrapper mockAuthenticationContextWrapper,
            IAuthenticationResult authenticationResult)
        {
            var accountSession = await this.AuthenticateWithDiscoveryService(mockAuthenticationContextWrapper);

            Assert.AreEqual(accountSession, this.authenticationProvider.CurrentAccountSession, "Account session not cached correctly.");
            Assert.AreEqual(ServiceEndpointUrl, this.adalServiceInfo.BaseUrl, "Base URL not set.");
            Assert.AreEqual(ServiceResourceId, this.adalServiceInfo.ServiceResource, "Service resource not set.");
            Assert.AreEqual(authenticationResult.AccessToken, accountSession.AccessToken, "Unexpected access token set.");
            Assert.AreEqual(authenticationResult.AccessTokenType, accountSession.AccessTokenType, "Unexpected access token type set.");
            Assert.AreEqual(AccountType.ActiveDirectory, accountSession.AccountType, "Unexpected account type set.");
            Assert.IsTrue(accountSession.CanSignOut, "CanSignOut set to false.");
            Assert.AreEqual(this.adalServiceInfo.AppId, accountSession.ClientId, "Unexpected client ID set.");
            Assert.AreEqual(authenticationResult.ExpiresOn, accountSession.ExpiresOnUtc, "Unexpected expiration set.");
            Assert.IsNull(accountSession.UserId, "Unexpected user ID set.");
        }

        public async Task<AccountSession> AuthenticateWithDiscoveryService(
            MockAuthenticationContextWrapper mockAuthenticationContextWrapper,
            DiscoveryServiceResponse discoveryServiceResponse = null)
        {
            var mockAuthenticationResult = new MockAuthenticationResult();
            mockAuthenticationResult.SetupGet(result => result.AccessToken).Returns("discoveryResource");

            mockAuthenticationContextWrapper.Setup(wrapper => wrapper.AcquireTokenSilentAsync(
                It.Is<string>(resource => resource.Equals(Constants.Authentication.ActiveDirectoryDiscoveryResource)),
                It.Is<string>(clientId => clientId.Equals(this.adalServiceInfo.AppId)))).Throws(new Exception());

            mockAuthenticationContextWrapper.Setup(wrapper => wrapper.AcquireToken(
                It.Is<string>(resource => resource.Equals(Constants.Authentication.ActiveDirectoryDiscoveryResource)),
                It.Is<string>(clientId => clientId.Equals(this.adalServiceInfo.AppId)),
                It.Is<Uri>(returnUri => returnUri.ToString().Equals(this.adalServiceInfo.ReturnUrl)),
                PromptBehavior.Auto,
                UserIdentifier.AnyUser)).Returns(mockAuthenticationResult.Object);

            if (discoveryServiceResponse == null)
            {
                discoveryServiceResponse = new DiscoveryServiceResponse
                {
                    Value = new List<DiscoveryService>
                    {
                        new DiscoveryService
                        {
                            Capability = Constants.Authentication.MyFilesCapability,
                            ServiceApiVersion = this.adalServiceInfo.OneDriveServiceEndpointVersion,
                            ServiceEndpointUri = ServiceEndpointUrl,
                            ServiceResourceId = ServiceResourceId,
                        }
                    }
                };
            }

            var requestBodyString = this.serializer.SerializeObject(discoveryServiceResponse);

            AccountSession accountSession;

            using (var stringContent = new StringContent(requestBodyString))
            {
                this.httpResponseMessage.Content = stringContent;
                this.authenticationProvider.authenticationContextWrapper = mockAuthenticationContextWrapper.Object;

                accountSession = await this.authenticationProvider.AuthenticateAsync();
            }

            return accountSession;
        }*/
    }
}
