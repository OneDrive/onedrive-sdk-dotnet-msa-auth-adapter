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
    public class MsaAuthenticationProvider : IAuthenticationProvider
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
        /// Constructs an <see cref="MsaAuthenticationProvider"/>.
        /// </summary>
        public MsaAuthenticationProvider(string appId, string returnUrl, string[] scopes)
            : this(appId, null, returnUrl, scopes)
        {
        }

        /// <summary>
        /// Constructs an <see cref="MsaAuthenticationProvider"/>.
        /// </summary>
        public MsaAuthenticationProvider(string appId, string clientSecret, string returnUrl, string[] scopes)
            : this(appId, clientSecret, returnUrl, scopes, /* httpProvider */ null, /* credentialCache */ null)
        {
        }

        /// <summary>
        /// Constructs an <see cref="MsaAuthenticationProvider"/>.
        /// </summary>
        public MsaAuthenticationProvider(
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

            this.httpProvider = httpProvider ?? new HttpProvider();
            this.CredentialCache = credentialCache ?? new CredentialCache();
            this.webAuthenticationUi = new FormsWebAuthenticationUi();
        }

#elif WINSTORE

        /// <summary>
        /// Constructs an <see cref="AuthenticationProvider"/>.
        /// </summary>
        public MsaAuthenticationProvider(string appId, string returnUrl, string[] scopes)
            : this (appId, returnUrl, scopes, /* httpProvider */ null, /* credentialCache */ null)
        {
        }

        /// <summary>
        /// Constructs an <see cref="MsaAuthenticationProvider"/>.
        /// </summary>
        public MsaAuthenticationProvider(
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

            this.httpProvider = httpProvider ?? new HttpProvider();
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
        public async Task AuthenticateRequestAsync(HttpRequestMessage request)
        {
            var authResult = await this.ProcessCachedAccountSessionAsync(this.CurrentAccountSession).ConfigureAwait(false);

            if (authResult == null)
            {
                throw new ServiceException(
                    new Error
                    {
                        Code = OAuthConstants.ErrorCodes.AuthenticationFailure,
                        Message = "Unable to retrieve a valid account session for the user. Please call AuthenticateUserAsync to prompt the user to re-authenticate."
                    });
            }

            if (!string.IsNullOrEmpty(authResult.AccessToken))
            {
                var tokenTypeString = string.IsNullOrEmpty(authResult.AccessTokenType)
                    ? "bearer"
                    : authResult.AccessTokenType;
                request.Headers.Authorization = new AuthenticationHeaderValue(tokenTypeString, authResult.AccessToken);
            }
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

                    await this.webAuthenticationUi.AuthenticateAsync(requestUri, new Uri(this.returnUrl)).ConfigureAwait(false);
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
            var authResult = await this.GetAuthenticationResultFromCacheAsync(userName).ConfigureAwait(false);

            if (authResult == null)
            {
                // Log the user in if we haven't already pulled their credentials from the cache.
                var code = await this.OAuthHelper.GetAuthorizationCodeAsync(
                    this.appId,
                    this.returnUrl,
                    this.scopes,
                    this.webAuthenticationUi,
                    userName).ConfigureAwait(false);

                if (!string.IsNullOrEmpty(code))
                {
                    authResult = await this.OAuthHelper.RedeemAuthorizationCodeAsync(
                        code,
                        this.appId,
                        this.clientSecret,
                        this.returnUrl,
                        this.scopes).ConfigureAwait(false);
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
            var accountSession = await this.ProcessCachedAccountSessionAsync(this.CurrentAccountSession).ConfigureAwait(false);

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

            var processedResult = await this.ProcessCachedAccountSessionAsync(cacheResult).ConfigureAwait(false);

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
                        this.scopes).ConfigureAwait(false);

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
