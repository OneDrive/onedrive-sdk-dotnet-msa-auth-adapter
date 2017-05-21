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

#if XamarinAndroid
    using Android.Content;
#endif

#if NETFX_CORE
    using Windows.Security.Authentication.Web;
    using Windows.System.Profile;    
#endif

    /// <summary>
    /// A default <see cref="IAuthenticationProvider"/> implementation.
    /// </summary>
    public class MsaAuthenticationProvider : IAuthenticationProvider
    {
        internal readonly string clientId;
        internal string clientSecret;
        internal string returnUrl;
        internal string[] scopes;
        
        private OAuthHelper oAuthHelper;

        internal ICredentialVault credentialVault;
        internal IWebAuthenticationUi webAuthenticationUi;

#if DESKTOP
        /// <summary>
        /// Constructs an <see cref="AuthenticationProvider"/>.
        /// </summary>
        public MsaAuthenticationProvider(string clientId, string returnUrl, string[] scopes)
            : this(clientId, /*clientSecret*/ null, returnUrl, scopes, /* credentialCache */ null, /* credentialVault */ null)
        {
        }

        /// <summary>
        /// Constructs an <see cref="AuthenticationProvider"/>.
        /// </summary>
        public MsaAuthenticationProvider(string clientId, string returnUrl, string[] scopes, ICredentialVault credentialVault)
            : this(clientId, /*clientSecret*/ null, returnUrl, scopes, /* credentialCache */ null, credentialVault)
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
            CredentialCache credentialCache,
            ICredentialVault credentialVault)
            : this(clientId, clientSecret, returnUrl, scopes, credentialCache)
        {
            if (credentialVault != null)
            {
                this.CredentialCache.BeforeAccess = cacheArgs =>
                {
                    credentialVault.RetrieveCredentialCache(cacheArgs.CredentialCache);
                    cacheArgs.CredentialCache.HasStateChanged = false;
                };
                this.CredentialCache.AfterAccess = cacheArgs =>
                {
                    if (cacheArgs.CredentialCache.HasStateChanged)
                    {
                        credentialVault.AddCredentialCacheToVault(cacheArgs.CredentialCache);
                    }
                };
            }
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

#elif NETFX_CORE

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
                this.CredentialCache.BeforeAccess = cacheArgs =>
                    {
                        credentialVault.RetrieveCredentialCache(cacheArgs.CredentialCache);
                        cacheArgs.CredentialCache.HasStateChanged = false;
                    };
                this.CredentialCache.AfterAccess = cacheArgs =>
                    {
                        if (cacheArgs.CredentialCache.HasStateChanged)
                        {
                            credentialVault.AddCredentialCacheToVault(cacheArgs.CredentialCache);
                        }
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
#if WINRT            
            this.webAuthenticationUi = new WebAuthenticationBrokerWebAuthenticationUi();
#elif WINDOWS_UWP
            // WebAuthenticationBroker is not supported on Windows 10 IoT Core, so if we're running UWP,
            // we need to first check if we're running on IoT Core. If we are, we fall back to our
            // own implementation.

            // Our method of detection here isn't bulletproof--more non-IoT device families could fall under
            // this namespace in the future. Unfortunately, using API detection won't work, because the API
            // is AVAILABLE in IoT, it just doesn't actually work.
            if (AnalyticsInfo.VersionInfo.DeviceFamily == "Windows.IoT")
            {
                this.webAuthenticationUi = new IotCoreFriendlyWebAuthenticationUi();
            }
            else
            {
                this.webAuthenticationUi = new WebAuthenticationBrokerWebAuthenticationUi();
            }
#endif
        }

#elif XamarinAndroid

        /// <summary>
        /// Constructs an <see cref="AuthenticationProvider"/>.
        /// </summary>
        public MsaAuthenticationProvider(Context context, string clientId, string returnUrl, string[] scopes)
            : this(context, clientId, /*clientSecret*/ null, returnUrl, scopes, /* credentialCache */ null, /* credentialVault */ null)
        {
        }

        /// <summary>
        /// Constructs an <see cref="AuthenticationProvider"/>.
        /// </summary>
        public MsaAuthenticationProvider(Context context, string clientId, string returnUrl, string[] scopes, ICredentialVault credentialVault)
            : this(context, clientId, /*clientSecret*/ null, returnUrl, scopes, /* credentialCache */ null, credentialVault)
        {
        }

        /// <summary>
        /// Constructs an <see cref="MsaAuthenticationProvider"/>.
        /// </summary>
        public MsaAuthenticationProvider(
            Context context,
            string clientId,
            string clientSecret,
            string returnUrl,
            string[] scopes,
            CredentialCache credentialCache,
            ICredentialVault credentialVault)
            : this(context, clientId, clientSecret, returnUrl, scopes, credentialCache)
        {
            if (credentialVault != null)
            {
                this.CredentialCache.BeforeAccess = cacheArgs =>
                {
                    credentialVault.RetrieveCredentialCache(cacheArgs.CredentialCache);
                    cacheArgs.CredentialCache.HasStateChanged = false;
                };
                this.CredentialCache.AfterAccess = cacheArgs =>
                {
                    if (cacheArgs.CredentialCache.HasStateChanged)
                    {
                        credentialVault.AddCredentialCacheToVault(cacheArgs.CredentialCache);
                    }
                };
            }
        }

        /// <summary>
        /// Constructs an <see cref="MsaAuthenticationProvider"/>.
        /// </summary>
        public MsaAuthenticationProvider(
            Context context,
            string clientId,
            string clientSecret,
            string returnUrl,
            string[] scopes,
            CredentialCache credentialCache)
            : this(clientId, clientSecret, returnUrl, scopes, credentialCache, new AndroidWebAuthenticationUi(context))
        {
        }

        /// <summary>
        /// Constructs an <see cref="MsaAuthenticationProvider"/>.
        /// </summary>
        internal MsaAuthenticationProvider(
            string clientId,
            string clientSecret,
            string returnUrl,
            string[] scopes,
            CredentialCache credentialCache,
            IWebAuthenticationUi authenticationUi)
        {
            this.clientId = clientId;
            this.clientSecret = clientSecret;
            this.returnUrl = returnUrl;
            this.scopes = scopes;

            this.CredentialCache = credentialCache ?? new CredentialCache();
            this.oAuthHelper = new OAuthHelper();
            this.webAuthenticationUi = authenticationUi;
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
        public virtual async Task SignOutAsync()
        {
            if (this.IsAuthenticated)
            {
                await this.SignOutOfBrowserAsync();
                
                this.DeleteUserCredentialsFromCache(this.CurrentAccountSession);
                this.CurrentAccountSession = null;
            }
        }

        /// <summary>
        /// Get rid of any cookies in the browser
        /// </summary>
        /// <returns>Task for signout. When task is done, signout is complete.</returns>
        public async Task SignOutOfBrowserAsync()
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
        /// Retrieves the authentication token. Tries the to retrieve the most recently
        /// used credentials if available.
        /// </summary>
        /// <param name="userName">The login name of the user, if known.</param>
        /// <returns>The authentication token.</returns>
        public async Task RestoreMostRecentFromCacheOrAuthenticateUserAsync(string userName = null)
        {
            using (var httpProvider = new HttpProvider())
            {
                await this.RestoreMostRecentFromCacheOrAuthenticateUserAsync(httpProvider, userName).ConfigureAwait(false);
            }
        }

        /// <summary>
        /// Retrieves the authentication token. Tries the to retrieve the most recently
        /// used credentials if available.
        /// </summary>
        /// <param name="httpProvider">HttpProvider for any web requests needed for authentication</param>
        /// <param name="userName">The login name of the user, if known.</param>
        /// <returns>The authentication token.</returns>
        public async Task RestoreMostRecentFromCacheOrAuthenticateUserAsync(IHttpProvider httpProvider, string userName = null)
        {
            var authResult = await this.GetMostRecentAuthenticationResultFromCacheAsync(httpProvider).ConfigureAwait(false);

            if (authResult == null)
            {
                await this.AuthenticateUserAsync(httpProvider, userName);
            }
            else
            {
                this.CacheAuthResult(authResult);
            }
        }

        /// <summary>
        /// Retrieves the authentication token. Retrieves the most recently
        /// used credentials if available, without showing the sign in UI if credentials are unavailable.
        /// </summary>
        /// <param name="userName">The login name of the user, if known.</param>
        /// <returns>The authentication token.</returns>
        public async Task<bool> RestoreMostRecentFromCacheAsync(string userName = null)
        {
            using (var httpProvider = new HttpProvider())
            {
                return await this.RestoreMostRecentFromCacheAsync(httpProvider, userName).ConfigureAwait(false);
            }
        }

        /// <summary>
        /// Retrieves the authentication token. Retrieves the most recently
        /// used credentials if available, without showing the sign in UI if credentials are unavailable.
        /// </summary>
        /// <param name="httpProvider">HttpProvider for any web requests needed for authentication</param>
        /// <param name="userName">The login name of the user, if known.</param>
        /// <returns>The authentication token.</returns>
        public async Task<bool> RestoreMostRecentFromCacheAsync(IHttpProvider httpProvider, string userName = null)
        {
            var authResult = await this.GetMostRecentAuthenticationResultFromCacheAsync(httpProvider).ConfigureAwait(false);
            if (authResult != null)
            {
                this.CacheAuthResult(authResult);
            }
            return authResult != null;
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
        /// <param name="httpProvider">HttpProvider for any web requests needed for authentication</param>
        /// <param name="userName">The login name of the user, if known.</param>
        /// <returns>The authentication token.</returns>
        public virtual async Task AuthenticateUserAsync(IHttpProvider httpProvider, string userName = null)
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

        internal async Task<AccountSession> GetMostRecentAuthenticationResultFromCacheAsync(IHttpProvider httpProvider)
        {
            var cacheResult = this.CredentialCache.GetMostRecentlyUsedResultFromCache();

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

        internal virtual async Task<AccountSession> ProcessCachedAccountSessionAsync(AccountSession accountSession, IHttpProvider httpProvider)
        {
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
