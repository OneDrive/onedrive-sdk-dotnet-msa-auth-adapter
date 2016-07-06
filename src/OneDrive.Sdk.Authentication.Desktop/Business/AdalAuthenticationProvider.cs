// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.OneDrive.Sdk.Authentication
{
    using System;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;

    using Microsoft.Graph;
    using Microsoft.IdentityModel.Clients.ActiveDirectory;

    public class AdalAuthenticationProvider : AdalAuthenticationProviderBase
    {
        private readonly string clientSecret;
        private readonly X509Certificate2 clientCertificate;

        private OAuthHelper oAuthHelper;

        internal IWebAuthenticationUi webAuthenticationUi;

        internal AdalAuthenticationProvider(
            string clientId,
            string returnUrl,
            IAuthenticationContextWrapper authenticationContextWrapper)
            : base(clientId, returnUrl, authenticationContextWrapper)
        {
            this.AuthenticateUser = this.PromptUserForAuthenticationAsync;
            this.AuthenticateUserSilently = this.SilentlyAuthenticateUserAsync;

            this.oAuthHelper = new OAuthHelper();
        }

        internal AdalAuthenticationProvider(
            string clientId,
            string clientSecret,
            string returnUrl,
            IAuthenticationContextWrapper authenticationContextWrapper)
            : base(clientId, returnUrl, authenticationContextWrapper)
        {
            this.clientSecret = clientSecret;

            this.AuthenticateUser = this.PromptUserForAuthenticationWithClientSecretAsync;
            this.AuthenticateUserSilently = this.SilentlyAuthenticateUserWithClientSecretAsync;

            this.oAuthHelper = new OAuthHelper();
        }

        internal AdalAuthenticationProvider(
            string clientId,
            X509Certificate2 clientCertificate,
            string returnUrl,
            IAuthenticationContextWrapper authenticationContextWrapper)
            : base (clientId, returnUrl, authenticationContextWrapper)
        {
            this.clientCertificate = clientCertificate;

            this.AuthenticateUser = this.PromptUserForAuthenticationWithClientCertificateAsync;
            this.AuthenticateUserSilently = this.SilentlyAuthenticateUserWithClientCertificateAsync;

            this.oAuthHelper = new OAuthHelper();
        }

        public AdalAuthenticationProvider(
            string clientId,
            string returnUrl,
            AuthenticationContext authenticationContext = null)
            : this(
                  clientId,
                  /* clientSecret */ null,
                  /* clientCertificate */ null,
                  returnUrl,
                  authenticationContext)
        {
        }

        public AdalAuthenticationProvider(
            string clientId,
            string clientSecret,
            string returnUrl,
            AuthenticationContext authenticationContext = null)
            : this(
                  clientId,
                  clientSecret,
                  /* clientCertificate */ null,
                  returnUrl,
                  authenticationContext)
        {
        }

        public AdalAuthenticationProvider(
            string clientId,
            X509Certificate2 clientCertificate,
            string returnUrl,
            AuthenticationContext authenticationContext = null)
            : this(
                  clientId,
                  /* clientSecret */ null,
                  clientCertificate,
                  returnUrl,
                  authenticationContext)
        {
        }

        private AdalAuthenticationProvider(
            string clientId,
            string clientSecret,
            X509Certificate2 clientCertificate,
            string returnUrl,
            AuthenticationContext authenticationContext)
            : base(clientId, returnUrl, authenticationContext)
        {
            this.clientSecret = clientSecret;
            this.clientCertificate = clientCertificate;

            this.oAuthHelper = new OAuthHelper();
            this.webAuthenticationUi = new FormsWebAuthenticationUi();

            if (this.clientCertificate != null)
            {
                this.AuthenticateUser = this.PromptUserForAuthenticationWithClientCertificateAsync;
                this.AuthenticateUserSilently = this.SilentlyAuthenticateUserWithClientCertificateAsync;
            }
            else if (!string.IsNullOrEmpty(this.clientSecret))
            {
                this.AuthenticateUser = this.PromptUserForAuthenticationWithClientSecretAsync;
                this.AuthenticateUserSilently = this.SilentlyAuthenticateUserWithClientSecretAsync;
            }
            else
            {
                this.AuthenticateUser = this.PromptUserForAuthenticationAsync;
                this.AuthenticateUserSilently = this.SilentlyAuthenticateUserAsync;
            }
        }

        /// <summary>
        /// Gets the client certificate for the class. Used for unit testing.
        /// </summary>
        internal X509Certificate2 ClientCertificate
        {
            get
            {
                return this.clientCertificate;
            }
        }

        /// <summary>
        /// Gets the client secret for the class. Used for unit testing.
        /// </summary>
        internal string ClientSecret
        {
            get
            {
                return this.clientSecret;
            }
        }

        protected override AuthenticateUserDelegate AuthenticateUser { get; set; }

        protected override AuthenticateUserSilentlyDelegate AuthenticateUserSilently { get; set; }

        public Task AuthenticateUserWithAuthorizationCodeAsync(string authorizationCode)
        {
            return this.AuthenticateUserWithAuthorizationCodeAsync(authorizationCode, /* serviceResourceId */ null);
        }

        public async Task AuthenticateUserWithAuthorizationCodeAsync(string authorizationCode, string serviceResourceId)
        {
            if (string.IsNullOrEmpty(authorizationCode))
            {
                throw new ServiceException(
                    new Error
                    {
                        Code = OAuthConstants.ErrorCodes.AuthenticationFailure,
                        Message = "Authorization code is required to authenticate a user with an authorization code."
                    });
            }

            if (string.IsNullOrEmpty(returnUrl))
            {
                throw new ServiceException(
                    new Error
                    {
                        Code = OAuthConstants.ErrorCodes.AuthenticationFailure,
                        Message = "Return URL is required to authenticate a user with an authorization code."
                    });
            }

            this.currentServiceResourceId = serviceResourceId;

            IAuthenticationResult authenticationResult = null;

            try
            {
                if (this.clientCertificate != null)
                {
                    var clientAssertionCertificate = new ClientAssertionCertificate(this.clientId, this.clientCertificate);
                    authenticationResult = await this.authenticationContextWrapper.AcquireTokenByAuthorizationCodeAsync(
                        authorizationCode,
                        new Uri(this.returnUrl),
                        clientAssertionCertificate,
                        serviceResourceId).ConfigureAwait(false);
                }
                else if (!string.IsNullOrEmpty(this.clientSecret))
                {
                    var clientCredential = this.GetClientCredentialForAuthentication(this.clientId, this.clientSecret);
                    authenticationResult = await this.authenticationContextWrapper.AcquireTokenByAuthorizationCodeAsync(
                        authorizationCode,
                        new Uri(this.returnUrl),
                        clientCredential,
                        serviceResourceId).ConfigureAwait(false);
                }
                else
                {
                    throw new ServiceException(
                    new Error
                    {
                        Code = OAuthConstants.ErrorCodes.AuthenticationFailure,
                        Message = "Client certificate or client secret is required to authenticate a user with an authorization code."
                    });
                }
            }
            catch (Exception exception)
            {
                BusinessAuthenticationExceptionHelper.HandleAuthenticationException(exception);
            }

            if (authenticationResult == null)
            {
                BusinessAuthenticationExceptionHelper.HandleAuthenticationException(null);
            }

            this.CurrentAccountSession = this.ConvertAuthenticationResultToAccountSession(authenticationResult);
        }

        public override Task AuthenticateUserWithRefreshTokenAsync(string refreshToken)
        {
            return this.AuthenticateUserWithRefreshTokenAsync(refreshToken, /* serviceResourceId */ null);
        }

        public override async Task AuthenticateUserWithRefreshTokenAsync(string refreshToken, string serviceResourceId)
        {
            if (string.IsNullOrEmpty(refreshToken))
            {
                throw new ServiceException(
                    new Error
                    {
                        Code = OAuthConstants.ErrorCodes.AuthenticationFailure,
                        Message = "Refresh token is required to authenticate a user with a refresh token."
                    });
            }

            this.currentServiceResourceId = serviceResourceId;

            IAuthenticationResult authenticationResult = null;

            try
            {
                if (this.clientCertificate != null)
                {
                    var clientAssertionCertificate = new ClientAssertionCertificate(this.clientId, this.clientCertificate);
                    authenticationResult = await this.authenticationContextWrapper.AcquireTokenByRefreshTokenAsync(
                        refreshToken,
                        clientAssertionCertificate,
                        serviceResourceId).ConfigureAwait(false);
                }
                else if (!string.IsNullOrEmpty(this.clientSecret))
                {
                    var clientCredential = this.GetClientCredentialForAuthentication(this.clientId, this.clientSecret);
                    authenticationResult = await this.authenticationContextWrapper.AcquireTokenByRefreshTokenAsync(
                        refreshToken,
                        clientCredential,
                        serviceResourceId).ConfigureAwait(false);
                }
                else
                {
                    authenticationResult = await this.authenticationContextWrapper.AcquireTokenByRefreshTokenAsync(
                        refreshToken,
                        this.clientId,
                        serviceResourceId).ConfigureAwait(false);
                }
            }
            catch (Exception exception)
            {
                BusinessAuthenticationExceptionHelper.HandleAuthenticationException(exception);
            }

            if (authenticationResult == null)
            {
                BusinessAuthenticationExceptionHelper.HandleAuthenticationException(null);
            }

            this.CurrentAccountSession = this.ConvertAuthenticationResultToAccountSession(authenticationResult);
        }

        private async Task<IAuthenticationResult> SilentlyAuthenticateUserAsync(
            string serviceResourceId,
            string userId,
            bool throwOnError)
        {
            IAuthenticationResult authenticationResult = null;

            var userIdentifier = this.GetUserIdentifierForAuthentication(userId);

            try
            {
                authenticationResult = await this.authenticationContextWrapper.AcquireTokenSilentAsync(
                    serviceResourceId,
                    clientId,
                    userIdentifier).ConfigureAwait(false);
            }
            catch (Exception)
            {
                if (throwOnError)
                {
                    throw;
                }
            }

            return authenticationResult;
        }

        private Task<IAuthenticationResult> PromptUserForAuthenticationAsync(string serviceResourceId, string userId)
        {
            var userIdentifier = this.GetUserIdentifierForAuthentication(userId);

            return Task.FromResult(
                this.authenticationContextWrapper.AcquireToken(
                    serviceResourceId,
                    clientId,
                    new Uri(returnUrl),
                    PromptBehavior.Auto,
                    userIdentifier));
        }

        private async Task<IAuthenticationResult> SilentlyAuthenticateUserWithClientSecretAsync(
            string serviceResourceId,
            string userId,
            bool throwOnError)
        {
            IAuthenticationResult authenticationResult = null;

            var clientCredential = this.GetClientCredentialForAuthentication(this.clientId, this.clientSecret);
            var userIdentifier = this.GetUserIdentifierForAuthentication(userId);

            try
            {
                authenticationResult = await this.authenticationContextWrapper.AcquireTokenSilentAsync(
                    serviceResourceId,
                    clientCredential,
                    userIdentifier).ConfigureAwait(false);
            }
            catch (Exception)
            {
                if (throwOnError)
                {
                    throw;
                }
            }

            return authenticationResult;
        }

        private async Task<IAuthenticationResult> PromptUserForAuthenticationWithClientSecretAsync(
            string serviceResourceId,
            string userId)
        {
            IAuthenticationResult authenticationResult = null;

            var clientCredential = this.GetClientCredentialForAuthentication(this.clientId, this.clientSecret);
            var userIdentifier = this.GetUserIdentifierForAuthentication(userId);
            var redirectUri = new Uri(returnUrl);

            var requestUri = new Uri(this.oAuthHelper.GetAuthorizationCodeRequestUrl(
                this.clientId,
                this.returnUrl,
                null,
                userId));

            var authenticationResponseValues = await webAuthenticationUi.AuthenticateAsync(
                requestUri,
                redirectUri).ConfigureAwait(false);

            OAuthErrorHandler.ThrowIfError(authenticationResponseValues);

            string code;
            if (authenticationResponseValues != null && authenticationResponseValues.TryGetValue("code", out code))
            {
                authenticationResult = await this.authenticationContextWrapper.AcquireTokenByAuthorizationCodeAsync(
                    code,
                    redirectUri,
                    clientCredential,
                    serviceResourceId).ConfigureAwait(false);
            }

            return authenticationResult;
        }

        private async Task<IAuthenticationResult> SilentlyAuthenticateUserWithClientCertificateAsync(
            string serviceResourceId,
            string userId,
            bool throwOnError)
        {
            IAuthenticationResult authenticationResult = null;

            var clientAssertionCertificate = new ClientAssertionCertificate(this.clientId, this.clientCertificate);
            var userIdentifier = this.GetUserIdentifierForAuthentication(userId);

            try
            {
                authenticationResult = await this.authenticationContextWrapper.AcquireTokenSilentAsync(
                    serviceResourceId,
                    clientAssertionCertificate,
                    userIdentifier).ConfigureAwait(false);
            }
            catch (Exception)
            {
                if (throwOnError)
                {
                    throw;
                }
            }

            return authenticationResult;
        }

        private async Task<IAuthenticationResult> PromptUserForAuthenticationWithClientCertificateAsync(
            string serviceResourceId,
            string userId)
        {
            IAuthenticationResult authenticationResult = null;

            var clientAssertionCertificate = new ClientAssertionCertificate(this.clientId, this.clientCertificate);
            var userIdentifier = this.GetUserIdentifierForAuthentication(userId);
            var redirectUri = new Uri(this.returnUrl);

            var requestUri = new Uri(this.oAuthHelper.GetAuthorizationCodeRequestUrl(
                this.clientId,
                this.returnUrl,
                null,
                userId));

            var authenticationResponseValues = await webAuthenticationUi.AuthenticateAsync(
                requestUri,
                redirectUri).ConfigureAwait(false);

            OAuthErrorHandler.ThrowIfError(authenticationResponseValues);

            string code;
            if (authenticationResponseValues != null && authenticationResponseValues.TryGetValue("code", out code))
            {
                authenticationResult = await this.authenticationContextWrapper.AcquireTokenByAuthorizationCodeAsync(
                    code,
                    redirectUri,
                    clientAssertionCertificate,
                    serviceResourceId).ConfigureAwait(false);
            }

            return authenticationResult;
        }

        private ClientCredential GetClientCredentialForAuthentication(string clientId, string clientSecret)
        {
            return new ClientCredential(clientId, clientSecret);
        }
    }
}
