// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.OneDrive.Sdk.Authentication
{
    using System;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Threading.Tasks;

    using Microsoft.Graph;

#if WINSTORE
    using Windows.Security.Authentication.Web;
#endif

    /// <summary>
    /// A default <see cref="IAuthenticationProvider"/> implementation.
    /// </summary>
    public class AuthenticationProvider : IAuthenticationProvider
    {
        private readonly string appId;
        private readonly string clientSecret;
        private readonly string returnUrl;
        private readonly string[] scopes;

        private IHttpProvider httpProvider;
        private OAuthHelper oAuthHelper;

        internal IWebAuthenticationUi webAuthenticationUi;

#if DESKTOP

        /// <summary>
        /// Constructs an <see cref="AuthenticationProvider"/>.
        /// </summary>
        public AuthenticationProvider(string appId, string returnUrl, string[] scopes)
            : this(appId, null, returnUrl, scopes)
        {
        }

        /// <summary>
        /// Constructs an <see cref="AuthenticationProvider"/>.
        /// </summary>
        public AuthenticationProvider(string appId, string clientSecret, string returnUrl, string[] scopes)
            : this(appId, clientSecret, returnUrl, scopes, /* httpProvider */ null, /* credentialCache */ null)
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
            CredentialCache credentialCache)
        {
            this.appId = appId;
            this.clientSecret = clientSecret;
            this.returnUrl = returnUrl;
            this.scopes = scopes;

            this.httpProvider = httpProvider;
            this.CredentialCache = credentialCache ?? new CredentialCache();
            this.webAuthenticationUi = new FormsWebAuthenticationUi();
        }

#elif WINSTORE

        /// <summary>
        /// Constructs an <see cref="AuthenticationProvider"/>.
        /// </summary>
        public AuthenticationProvider(string appId, string returnUrl, string[] scopes)
            : this (appId, returnUrl, scopes, /* httpProvider */ null, /* credentialCache */ null)
        {
        }

        /// <summary>
        /// Constructs an <see cref="AuthenticationProvider"/>.
        /// </summary>
        public AuthenticationProvider(
            string appId,
            string returnUrl,
            string[] scopes,
            IHttpProvider httpProvider,
            CredentialCache credentialCache)
        {
            this.appId = appId;
            this.clientSecret = null;

            this.returnUrl = string.IsNullOrEmpty(returnUrl)
                ? WebAuthenticationBroker.GetCurrentApplicationCallbackUri().ToString()
                : returnUrl;

            this.scopes = scopes;

            this.httpProvider = httpProvider;
            this.CredentialCache = credentialCache ?? new CredentialCache();

            this.webAuthenticationUi = new WebAuthenticationBrokerWebAuthenticationUi();
        }

#endif

        public CredentialCache CredentialCache { get; private set; }

        public AccountSession CurrentAccountSession { get; set; }

        internal OAuthHelper OAuthHelper
        {
            get
            {
                if (this.oAuthHelper == null)
                {
                    this.oAuthHelper = new OAuthHelper(this.httpProvider);
                }

                return this.oAuthHelper;
            }

            set
            {
                this.oAuthHelper = value;
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
        /// Signs the current user out.
        /// </summary>
        public async Task SignOutAsync()
        {
            if (this.CurrentAccountSession != null)
            {
                if (this.webAuthenticationUi != null)
                {
                    var requestUri = new Uri(this.OAuthHelper.GetSignOutUrl(this.appId, this.returnUrl));

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

        /// <summary>
        /// Retrieves the authentication token.
        /// </summary>
        /// <param name="userName">The login name of the user, if known.</param>
        /// <returns>The authentication token.</returns>
        public async Task AuthenticateUserAsync(string userName = null)
        {
            var authResult = await this.GetAuthenticationResultFromCacheAsync(userName);

            if (authResult == null)
            {
                // Log the user in if we haven't already pulled their credentials from the cache.
                var code = await this.OAuthHelper.GetAuthorizationCodeAsync(
                    this.appId,
                    this.returnUrl,
                    this.scopes,
                    this.webAuthenticationUi,
                    userName);

                if (!string.IsNullOrEmpty(code))
                {
                    authResult = await this.OAuthHelper.RedeemAuthorizationCodeAsync(
                        code,
                        this.appId,
                        this.clientSecret,
                        this.returnUrl,
                        this.scopes);
                }

                if (authResult == null || string.IsNullOrEmpty(authResult.AccessToken))
                {
                    throw new ServiceException(
                        new Error
                        {
                            Code = OAuthConstants.ErrorCodes.AuthenticationFailure,
                            Message = "Failed to retrieve a valid authentication token for the user."
                        });
                }
            }

            this.CacheAuthResult(authResult);
        }

        internal async Task<AccountSession> GetAuthenticationResultFromCacheAsync(string userId)
        {
            var accountSession = await this.ProcessCachedAccountSessionAsync(this.CurrentAccountSession);

            if (accountSession != null)
            {
                return accountSession;
            }

            if (string.IsNullOrEmpty(userId) && this.CurrentAccountSession != null)
            {
                userId = this.CurrentAccountSession.UserId;
            }

            var cacheResult = this.CredentialCache.GetResultFromCache(
                this.appId,
                userId);

            var processedResult = await this.ProcessCachedAccountSessionAsync(cacheResult);

            if (processedResult == null && cacheResult != null)
            {
                this.CredentialCache.DeleteFromCache(cacheResult);
                this.CurrentAccountSession = null;

                return null;
            }

            return processedResult;
        }

        internal async Task<AccountSession> ProcessCachedAccountSessionAsync(AccountSession accountSession)
        {
            if (accountSession != null)
            {
                var shouldRefresh = accountSession.ShouldRefresh;

                // If we don't have an access token or it's expiring see if we can refresh the access token.
                if (shouldRefresh && accountSession.CanRefresh)
                {         
                    accountSession = await this.OAuthHelper.RedeemRefreshTokenAsync(
                        accountSession.RefreshToken,
                        this.appId,
                        this.clientSecret,
                        this.returnUrl,
                        this.scopes);

                    if (accountSession != null && !string.IsNullOrEmpty(accountSession.AccessToken))
                    {
                        return accountSession;
                    }
                }
                else if (!shouldRefresh)
                {
                    return accountSession;
                }
            }

            return null;
        }
    }
}
