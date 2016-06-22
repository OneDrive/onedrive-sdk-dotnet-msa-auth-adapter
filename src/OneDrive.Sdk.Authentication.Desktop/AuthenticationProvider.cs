// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.OneDrive.Sdk.Authentication
{
    using System;
    using System.Collections.Generic;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Text;
    using System.Threading.Tasks;

    using Microsoft.Graph;

    /// <summary>
    /// A default <see cref="IAuthenticationProvider"/> implementation.
    /// </summary>
    public abstract class AuthenticationProvider : IAuthenticationProvider
    {
        private string appId;
        private string clientSecret;
        private string returnUrl;
        private string[] scopes;

        private IHttpProvider httpProvider;
        private IOAuthRequestStringBuilder oAuthRequestStringBuilder;
        private IWebAuthenticationUi webAuthenticationUi;

        /// <summary>
        /// Constructs an <see cref="AuthenticationProvider"/>.
        /// </summary>
        public AuthenticationProvider(string appId, string returnUrl, string[] scopes)
            : this (appId, null, returnUrl, scopes)
        {
        }

        /// <summary>
        /// Constructs an <see cref="AuthenticationProvider"/>.
        /// </summary>
        public AuthenticationProvider(string appId, string clientSecret, string returnUrl, string[] scopes)
            : this(
                  appId,
                  clientSecret,
                  returnUrl,
                  scopes,
                  new HttpProvider(),
                  new FormsWebAuthenticationUi(),
                  new CredentialCache())
        {
        }

        /// <summary>
        /// Constructs an <see cref="AuthenticationProvider"/>.
        /// </summary>
        public AuthenticationProvider(
            string appId,
            string clientSecret,
            string returnUrl,
            string[] scopes,
            IHttpProvider httpProvider,
            IWebAuthenticationUi webAuthenticationUi,
            CredentialCache credentialCache)
        {
            this.appId = appId;
            this.clientSecret = clientSecret;
            this.returnUrl = returnUrl;
            this.scopes = scopes;

            this.httpProvider = httpProvider;
            this.webAuthenticationUi = webAuthenticationUi;
            this.CredentialCache = credentialCache ?? new CredentialCache();
        }

        public CredentialCache CredentialCache { get; private set; }

        public AccountSession CurrentAccountSession { get; set; }

        internal IOAuthRequestStringBuilder OAuthRequestStringBuilder
        {
            get
            {
                if (this.oAuthRequestStringBuilder == null)
                {
                    this.oAuthRequestStringBuilder = new OAuthRequestStringBuilder();
                }

                return this.oAuthRequestStringBuilder;
            }

            set
            {
                this.oAuthRequestStringBuilder = value;
            }
        }

        /// <summary>
        /// Authenticates the provided request object.
        /// </summary>
        /// <param name="request">The <see cref="HttpRequestMessage"/> to authenticate.</param>
        /// <returns>The task to await.</returns>
        public Task AuthenticateRequestAsync(HttpRequestMessage request)
        {
            if (this.CurrentAccountSession == null)
            {
                throw new ServiceException(
                    new Error
                    {
                        Code = OAuthConstants.ErrorCodes.AuthenticationFailure,
                        Message = "AuthenticateAsync must be called before AuthenticateRequestAsync."
                    });
            }

            if (!string.IsNullOrEmpty(this.CurrentAccountSession.AccessToken))
            {
                var tokenTypeString = string.IsNullOrEmpty(this.CurrentAccountSession.AccessTokenType)
                    ? "bearer"
                    : this.CurrentAccountSession.AccessTokenType;
                request.Headers.Authorization = new AuthenticationHeaderValue(tokenTypeString, this.CurrentAccountSession.AccessToken);
            }

            return Task.FromResult(0);
        }

        /// <summary>
        /// Retrieves the authentication token.
        /// </summary>
        /// <param name="userName">The login name of the user, if known.</param>
        /// <returns>The authentication token.</returns>
        public virtual async Task<AccountSession> AuthenticateUserAsync(string userName = null)
        {
            var cachedResult = await this.GetAuthenticationResultFromCacheAsync(userName);

            this.CurrentAccountSession = await this.GetAuthenticationResultAsync(userName);

            if (this.CurrentAccountSession == null || string.IsNullOrEmpty(this.CurrentAccountSession.AccessToken))
            {
                throw new ServiceException(
                    new Error
                    {
                        Code = OAuthConstants.ErrorCodes.AuthenticationFailure,
                        Message = "Failed to retrieve a valid authentication token for the user."
                    });
            }

            this.CredentialCache.AddToCache(this.CurrentAccountSession);

            return this.CurrentAccountSession;
        }

        /// <summary>
        /// Signs the current user out.
        /// </summary>
        public async Task SignOutAsync()
        {
            if (this.CurrentAccountSession != null)
            {
                if (this.webAuthenticationUi != null)
                {
                    var requestUri = new Uri(string.Format(
                    "{0}?client_id={1}&redirect_uri={2}",
                    OAuthConstants.MicrosoftAccountSignOutUrl,
                    this.appId,
                    this.returnUrl));

                    await this.webAuthenticationUi.AuthenticateAsync(requestUri, new Uri(this.returnUrl));
                }

                this.DeleteUserCredentialsFromCache(this.CurrentAccountSession);
                this.CurrentAccountSession = null;
            }
        }

        protected void CacheAuthResult(AccountSession accountSession)
        {
            this.CurrentAccountSession = accountSession;

            if (this.CredentialCache != null)
            {
                this.CredentialCache.AddToCache(accountSession);
            }
        }

        protected void DeleteUserCredentialsFromCache(AccountSession accountSession)
        {
            if (this.CredentialCache != null)
            {
                this.CredentialCache.DeleteFromCache(accountSession);
            }
        }

        protected async Task<AccountSession> GetAuthenticationResultAsync(string userId)
        {
            AccountSession authResult = null;

            // Log the user in if we haven't already pulled their credentials from the cache.
            var code = await this.GetAuthorizationCodeAsync(userId);

            if (!string.IsNullOrEmpty(code))
            {
                authResult = await this.SendTokenRequestAsync(
                    this.OAuthRequestStringBuilder.GetCodeRedemptionRequestBody(
                        code,
                        this.appId,
                        this.returnUrl,
                        this.scopes,
                        this.clientSecret));
            }

            if (authResult != null)
            {
                this.CacheAuthResult(authResult);
            }

            return authResult;
        }

        protected async Task<AccountSession> GetAuthenticationResultFromCacheAsync(string userId)
        {
            await this.ProcessCachedAccountSessionAsync(this.CurrentAccountSession);

            if (this.CurrentAccountSession != null)
            {
                return this.CurrentAccountSession;
            }

            if (this.CredentialCache != null)
            {
                var cacheResult = this.CredentialCache.GetResultFromCache(
                    this.appId,
                    userId);

                await this.ProcessCachedAccountSessionAsync(cacheResult);

                if (cacheResult != null && this.CurrentAccountSession == null)
                {
                    this.CredentialCache.DeleteFromCache(cacheResult);

                    return null;
                }

                return cacheResult;
            }

            return null;
        }

        internal async Task<string> GetAuthorizationCodeAsync(string userId)
        {
            if (this.webAuthenticationUi != null)
            {
                var requestUri = new Uri(
                    this.OAuthRequestStringBuilder.GetAuthorizationCodeRequestUrl(
                        this.appId,
                        this.returnUrl,
                        this.scopes,
                        userId));

                var authenticationResponseValues = await this.webAuthenticationUi.AuthenticateAsync(
                    requestUri,
                    new Uri(this.returnUrl));

                OAuthErrorHandler.ThrowIfError(authenticationResponseValues);

                string code;
                if (authenticationResponseValues != null && authenticationResponseValues.TryGetValue("code", out code))
                {
                    return code;
                }
            }

            return null;
        }
        
        protected virtual Task<AccountSession> RefreshAccessTokenAsync(string refreshToken)
        {
            return this.SendTokenRequestAsync(
                this.OAuthRequestStringBuilder.GetRefreshTokenRequestBody(
                    refreshToken,
                    this.appId,
                    this.returnUrl,
                    this.scopes,
                    this.clientSecret));
        }

        internal async Task ProcessCachedAccountSessionAsync(AccountSession accountSession)
        {
            if (accountSession != null)
            {
                // If we don't have an access token or it's expiring see if we can refresh the access token.
                if (accountSession.ShouldRefresh && accountSession.CanRefresh)
                {         
                    accountSession = await this.RefreshAccessTokenAsync(accountSession.RefreshToken);

                    if (accountSession != null && !string.IsNullOrEmpty(accountSession.AccessToken))
                    {
                        this.CurrentAccountSession = accountSession;
                    }
                }
            }
        }
        
        internal async Task<AccountSession> SendTokenRequestAsync(string requestBodyString)
        {
            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Post, OAuthConstants.MicrosoftAccountTokenServiceUrl);

            httpRequestMessage.Content = new StringContent(requestBodyString, Encoding.UTF8, "application/x-www-form-urlencoded");

            using (var authResponse = await this.httpProvider.SendAsync(httpRequestMessage))
            using (var responseStream = await authResponse.Content.ReadAsStreamAsync())
            {
                var responseValues =
                    this.httpProvider.Serializer.DeserializeObject<IDictionary<string, string>>(
                        responseStream);

                if (responseValues != null)
                {
                    OAuthErrorHandler.ThrowIfError(responseValues);
                    return new AccountSession(responseValues, this.appId);
                }

                throw new ServiceException(
                    new Error
                    {
                        Code = OAuthConstants.ErrorCodes.AuthenticationFailure,
                        Message = "Authentication failed. No response values returned from authentication flow."
                    });
            }
        }
    }
}
