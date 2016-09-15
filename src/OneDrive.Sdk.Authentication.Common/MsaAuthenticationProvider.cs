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
        private readonly string clientId;
        private readonly string clientSecret;
        private readonly string returnUrl;
        private readonly string[] scopes;
        
        private OAuthHelper oAuthHelper;

        internal ICredentialVault credentialVault;
        internal IWebAuthenticationUi webAuthenticationUi;

#if DESKTOP

        /// <summary>
        /// Constructs an <see cref="MsaAuthenticationProvider"/>.
        /// </summary>
        public MsaAuthenticationProvider(string clientId, string returnUrl, string[] scopes)
            : this(clientId, /* clientSecret */ null, returnUrl, scopes, /* httpProvider */ null)
        {
        }

        /// <summary>
        /// Constructs an <see cref="MsaAuthenticationProvider"/>.
        /// </summary>
        public MsaAuthenticationProvider(
            string clientId,
            string clientSecret,
            string returnUrl,
            string[] scopes,
            CredentialCache credentialCache)
        {
            this.clientId = clientId;
            this.clientSecret = clientSecret;
            this.returnUrl = returnUrl;
            this.scopes = scopes;

            this.CredentialCache = credentialCache ?? new CredentialCache();
            this.oAuthHelper = new OAuthHelper();
            this.webAuthenticationUi = new FormsWebAuthenticationUi();
        }

#elif WINSTORE

        /// <summary>
        /// Constructs an <see cref="AuthenticationProvider"/>.
        /// </summary>
        public MsaAuthenticationProvider(string clientId, string returnUrl, string[] scopes)
            : this(clientId, returnUrl, scopes, /* credentialCache */ null, /* credentialVault */ null)
        {
        }

        /// <summary>
        /// Constructs an <see cref="AuthenticationProvider"/>.
        /// </summary>
        public MsaAuthenticationProvider(string clientId, string returnUrl, string[] scopes, ICredentialVault credentialVault)
            : this(clientId, returnUrl, scopes, /* credentialCache */ null, credentialVault)
        {
        }

        /// <summary>
        /// Constructs an <see cref="MsaAuthenticationProvider"/>.
        /// </summary>
        public MsaAuthenticationProvider(
            string clientId,
            string returnUrl,
            string[] scopes,
            CredentialCache credentialCache,
            ICredentialVault credentialVault)
            : this(clientId, returnUrl, scopes, credentialCache)
        {
            if (credentialVault != null)
            {
                this.CredentialCache.BeforeAccess = cacheArgs => credentialVault.RetrieveCredentialCache(cacheArgs.CredentialCache);
                this.CredentialCache.AfterAccess = cacheArgs =>
                    {
                        credentialVault.AddCredentialCacheToVault(cacheArgs.CredentialCache);
                    };
            }
        }

        /// <summary>
        /// Constructs an <see cref="MsaAuthenticationProvider"/>.
        /// </summary>
        public MsaAuthenticationProvider(
            string clientId,
            string returnUrl,
            string[] scopes,
            CredentialCache credentialCache)
        {
            this.clientId = clientId;
            this.clientSecret = null;

            this.returnUrl = string.IsNullOrEmpty(returnUrl)
                ? WebAuthenticationBroker.GetCurrentApplicationCallbackUri().ToString()
                : returnUrl;

            this.scopes = scopes;

            this.CredentialCache = credentialCache ?? new CredentialCache();
            this.oAuthHelper = new OAuthHelper();
            this.webAuthenticationUi = new WebAuthenticationBrokerWebAuthenticationUi();
        }

#endif

        public CredentialCache CredentialCache { get; private set; }

        public AccountSession CurrentAccountSession { get; set; }

        /// <summary>
        /// Gets whether or not the current client is authenticated.
        /// </summary>
        public bool IsAuthenticated
        {
            get
            {
                return this.CurrentAccountSession != null;
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
                    ? OAuthConstants.Headers.Bearer
                    : authResult.AccessTokenType;
                request.Headers.Authorization = new AuthenticationHeaderValue(tokenTypeString, authResult.AccessToken);
            }
        }

        /// <summary>
        /// Signs the current user out.
        /// </summary>
        public async Task SignOutAsync()
        {
            if (this.IsAuthenticated)
            {
                if (this.webAuthenticationUi != null)
                {
                    var requestUri = new Uri(this.oAuthHelper.GetSignOutUrl(this.clientId, this.returnUrl));

                    try
                    {
                        await this.webAuthenticationUi.AuthenticateAsync(requestUri, new Uri(this.returnUrl)).ConfigureAwait(false);
                    }
                    catch (ServiceException serviceException)
                    {
                        // Sometimes WebAuthenticationBroker can throw authentication cancelled on the sign out call. We don't care
                        // about this so swallow the error.
                        if (!serviceException.IsMatch(OAuthConstants.ErrorCodes.AuthenticationCancelled))
                        {
                            throw;
                        }
                    }
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

            if (accountSession.RefreshToken != null)
            {
                var credentialVault = new CredentialVault(this.clientId);
                credentialVault.AddAccountSessionToVault(accountSession);
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
            using (var httpProvider = new HttpProvider())
            {
                await this.AuthenticateUserAsync(httpProvider, userName).ConfigureAwait(false);
            }
        }

        /// <summary>
        /// Retrieves the authentication token.
        /// </summary>
        /// <param name="userName">The login name of the user, if known.</param>
        /// <returns>The authentication token.</returns>
        public async Task AuthenticateUserAsync(IHttpProvider httpProvider, string userName = null)
        {
            var authResult = await this.GetAuthenticationResultFromCacheAsync(userName, httpProvider).ConfigureAwait(false);

            if (authResult == null)
            {
                // Log the user in if we haven't already pulled their credentials from the cache.
                var code = await this.oAuthHelper.GetAuthorizationCodeAsync(
                    this.clientId,
                    this.returnUrl,
                    this.scopes,
                    this.webAuthenticationUi,
                    userName).ConfigureAwait(false);

                if (!string.IsNullOrEmpty(code))
                {
                    authResult = await this.oAuthHelper.RedeemAuthorizationCodeAsync(
                        code,
                        this.clientId,
                        this.clientSecret,
                        this.returnUrl,
                        this.scopes,
                        httpProvider).ConfigureAwait(false);
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

        internal async Task<AccountSession> GetAuthenticationResultFromCacheAsync(string userId, IHttpProvider httpProvider)
        {
            var accountSession = await this.ProcessCachedAccountSessionAsync(this.CurrentAccountSession, httpProvider).ConfigureAwait(false);

            if (accountSession != null)
            {
                return accountSession;
            }

            if (string.IsNullOrEmpty(userId) && this.CurrentAccountSession != null)
            {
                userId = this.CurrentAccountSession.UserId;
            }

            var cacheResult = this.CredentialCache.GetResultFromCache(
                this.clientId,
                userId);

            var processedResult = await this.ProcessCachedAccountSessionAsync(cacheResult, httpProvider).ConfigureAwait(false);

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
            using (var httpProvider = new HttpProvider())
            {
                var processedAccountSession = await this.ProcessCachedAccountSessionAsync(accountSession, httpProvider).ConfigureAwait(false);
                return processedAccountSession;
            }
        }

        internal async Task<AccountSession> ProcessCachedAccountSessionAsync(AccountSession accountSession, IHttpProvider httpProvider)
        {
            if (accountSession == null)
            {
                var credentialVault = new CredentialVault(this.clientId);
                accountSession = credentialVault.RetrieveAccountSession();
            }

            if (accountSession != null)
            {
                var shouldRefresh = accountSession.ShouldRefresh;

                // If we don't have an access token or it's expiring see if we can refresh the access token.
                if (shouldRefresh && accountSession.CanRefresh)
                {
                    accountSession = await this.oAuthHelper.RedeemRefreshTokenAsync(
                        accountSession.RefreshToken,
                        this.clientId,
                        this.clientSecret,
                        this.returnUrl,
                        this.scopes,
                        httpProvider).ConfigureAwait(false);

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
