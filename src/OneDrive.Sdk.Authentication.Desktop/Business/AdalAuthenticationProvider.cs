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
        
        public AdalAuthenticationProvider(
            string clientId,
            string returnUrl,
            AuthenticationContext authenticationContext = null)
            : this(clientId, /* clientSecret */ null, /* clientCertificate */ null, returnUrl, authenticationContext)
        {
        }

        public AdalAuthenticationProvider(
            string clientId,
            string clientSecret,
            string returnUrl,
            AuthenticationContext authenticationContext = null)
            : this(clientId, clientSecret, /* clientCertificate */ null, returnUrl, authenticationContext)
        {
        }

        public AdalAuthenticationProvider(
            string clientId,
            X509Certificate2 clientCertificate,
            string returnUrl,
            AuthenticationContext authenticationContext = null)
            : this(clientId, /* clientSecret */ null, clientCertificate, returnUrl, authenticationContext)
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

        protected override AuthenticateUserDelegate AuthenticateUser { get; set; }

        protected override AuthenticateUserSilentlyDelegate AuthenticateUserSilently { get; set; }

        public override async Task AuthenticateUserWithRefreshTokenAsync(string refreshToken)
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

            AuthenticationResult authenticationResult = null;

            try
            {
                if (this.clientCertificate != null)
                {
                    var clientAssertionCertificate = new ClientAssertionCertificate(this.clientId, this.clientCertificate);
                    authenticationResult = await this.authenticationContext.AcquireTokenByRefreshTokenAsync(
                        refreshToken,
                        clientAssertionCertificate).ConfigureAwait(false);
                }
                else if (!string.IsNullOrEmpty(this.clientSecret))
                {
                    var clientCredential = this.GetClientCredentialForAuthentication(this.clientId, this.clientSecret);
                    authenticationResult = await this.authenticationContext.AcquireTokenByRefreshTokenAsync(
                        refreshToken,
                        clientCredential).ConfigureAwait(false);
                }
                else
                {
                    authenticationResult = await this.authenticationContext.AcquireTokenByRefreshTokenAsync(
                        refreshToken,
                        this.clientId).ConfigureAwait(false);
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

            this.CurrentAuthenticationResult = authenticationResult;
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

            AuthenticationResult authenticationResult = null;

            try
            {
                if (this.clientCertificate != null)
                {
                    var clientAssertionCertificate = new ClientAssertionCertificate(this.clientId, this.clientCertificate);
                    authenticationResult = await this.authenticationContext.AcquireTokenByRefreshTokenAsync(
                        refreshToken,
                        clientAssertionCertificate,
                        serviceResourceId).ConfigureAwait(false);
                }
                else if (!string.IsNullOrEmpty(this.clientSecret))
                {
                    var clientCredential = this.GetClientCredentialForAuthentication(this.clientId, this.clientSecret);
                    authenticationResult = await this.authenticationContext.AcquireTokenByRefreshTokenAsync(
                        refreshToken,
                        clientCredential,
                        serviceResourceId).ConfigureAwait(false);
                }
                else
                {
                    authenticationResult = await this.authenticationContext.AcquireTokenByRefreshTokenAsync(
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

            this.CurrentAuthenticationResult = authenticationResult;
        }

        private async Task<AuthenticationResult> SilentlyAuthenticateUserAsync(string serviceResourceId, string userId)
        {
            AuthenticationResult authenticationResult = null;

            var userIdentifier = this.GetUserIdentifierForAuthentication(userId);

            try
            {
                authenticationResult = await this.authenticationContext.AcquireTokenSilentAsync(
                    OAuthConstants.ActiveDirectoryDiscoveryResource,
                    clientId,
                    userIdentifier).ConfigureAwait(false);
            }
            catch (Exception)
            {
                // If an exception happens during silent authentication try interactive authentication.
            }

            return authenticationResult;
        }

        private Task<AuthenticationResult> PromptUserForAuthenticationAsync(string serviceResourceId, string userId)
        {
            var userIdentifier = this.GetUserIdentifierForAuthentication(userId);

            return Task.FromResult(
                this.authenticationContext.AcquireToken(
                    OAuthConstants.ActiveDirectoryDiscoveryResource,
                    clientId,
                    new Uri(returnUrl),
                    PromptBehavior.Auto,
                    userIdentifier));
        }

        private async Task<AuthenticationResult> SilentlyAuthenticateUserWithClientSecretAsync(
            string serviceResourceId,
            string userId = null)
        {
            AuthenticationResult authenticationResult = null;

            var clientCredential = this.GetClientCredentialForAuthentication(this.clientId, this.clientSecret);
            var userIdentifier = this.GetUserIdentifierForAuthentication(userId);

            try
            {
                authenticationResult = await this.authenticationContext.AcquireTokenSilentAsync(
                    serviceResourceId,
                    clientCredential,
                    userIdentifier).ConfigureAwait(false);
            }
            catch (Exception)
            {
                // If an exception happens during silent authentication try interactive authentication.
            }

            return authenticationResult;
        }

        private async Task<AuthenticationResult> PromptUserForAuthenticationWithClientSecretAsync(
            string serviceResourceId,
            string userId = null)
        {
            AuthenticationResult authenticationResult = null;

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
                authenticationResult = await this.authenticationContext.AcquireTokenByAuthorizationCodeAsync(
                    code,
                    redirectUri,
                    clientCredential,
                    serviceResourceId).ConfigureAwait(false);
            }

            return authenticationResult;
        }

        private async Task<AuthenticationResult> SilentlyAuthenticateUserWithClientCertificateAsync(
            string serviceResourceId,
            string userId = null)
        {
            AuthenticationResult authenticationResult = null;

            var clientAssertionCertificate = new ClientAssertionCertificate(this.clientId, this.clientCertificate);
            var userIdentifier = this.GetUserIdentifierForAuthentication(userId);

            try
            {
                authenticationResult = await this.authenticationContext.AcquireTokenSilentAsync(
                    serviceResourceId,
                    clientAssertionCertificate,
                    userIdentifier).ConfigureAwait(false);
            }
            catch (Exception)
            {
                // If an exception happens during silent authentication try interactive authentication.
            }

            return authenticationResult;
        }

        private async Task<AuthenticationResult> PromptUserForAuthenticationWithClientCertificateAsync(
            string serviceResourceId,
            string userId = null)
        {
            AuthenticationResult authenticationResult = null;

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
                authenticationResult = await this.authenticationContext.AcquireTokenByAuthorizationCodeAsync(
                    code,
                    redirectUri,
                    clientAssertionCertificate,
                    serviceResourceId).ConfigureAwait(false);
            }

            return authenticationResult;
        }

        private ClientCredential GetClientCredentialForAuthentication(string clientId, string clientSecret)
        {
            return string.IsNullOrEmpty(clientSecret)
                ? null
                : new ClientCredential(clientId, clientSecret);
        }
    }
}
