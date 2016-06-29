// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.OneDrive.Sdk.Authentication
{
    using System;
    using System.Net.Http.Headers;
    using System.Linq;
    using System.Net.Http;
    using System.Text;
    using System.Threading.Tasks;

    using Microsoft.Graph;
    using Microsoft.IdentityModel.Clients.ActiveDirectory;

    public abstract class AdalAuthenticationProviderBase : IAuthenticationProvider
    {
        internal AdalCredentialCache adalCredentialCache;
        internal string currentServiceResourceId;

        protected delegate Task<IAuthenticationResult> AuthenticateUserDelegate(string serviceResourceId, string userId);
        protected delegate Task<IAuthenticationResult> AuthenticateUserSilentlyDelegate(string serviceResourceId, string userId, bool throwOnError);

        protected readonly string clientId;
        protected readonly string returnUrl;

        protected IAuthenticationContextWrapper authenticationContextWrapper;

        /// <summary>
        /// Constructor for unit testing.
        /// </summary>
        /// <param name="clientId">The ID of the client.</param>
        /// <param name="returnUrl">The return URL for the client.</param>
        /// <param name="authenticationContextWrapper">The context for authenticating against AAD.</param>
        internal AdalAuthenticationProviderBase(
            string clientId,
            string returnUrl,
            IAuthenticationContextWrapper authenticationContextWrapper)
        {
            this.clientId = clientId;
            this.returnUrl = returnUrl;
            this.adalCredentialCache = new AdalCredentialCache(authenticationContextWrapper.TokenCache);
            this.authenticationContextWrapper = authenticationContextWrapper;
        }

        internal AdalAuthenticationProviderBase(
            string clientId,
            string returnUrl,
            AuthenticationContext authenticationContext)
        {
            if (string.IsNullOrEmpty(clientId))
            {
                throw new ServiceException(
                    new Error
                    {
                        Code = OAuthConstants.ErrorCodes.AuthenticationFailure,
                        Message = "AdalAuthenticationProvider requires a client ID for authenticating users."
                    });
            }

            this.clientId = clientId;
            this.returnUrl = returnUrl;

            if (authenticationContext != null)
            {
                this.authenticationContextWrapper = new AuthenticationContextWrapper(authenticationContext);
            }
            else
            {
                this.authenticationContextWrapper = new AuthenticationContextWrapper(
                    new AuthenticationContext(OAuthConstants.ActiveDirectoryAuthenticationServiceUrl));
            }

            this.adalCredentialCache = new AdalCredentialCache(this.authenticationContextWrapper.TokenCache);
        }

        /// <summary>
        /// Gets the <see cref="IAuthenticationContextWrapper"/> instance for the class.
        /// Used for unit testing.
        /// </summary>
        internal IAuthenticationContextWrapper AuthenticationContextWrapper
        {
            get
            {
                return this.authenticationContextWrapper;
            }
        }

        /// <summary>
        /// Gets the client ID for the class. Used for unit testing.
        /// </summary>
        internal string ClientId
        {
            get
            {
                return this.clientId;
            }
        }

        /// <summary>
        /// Gets the return URL for the class. Used for unit testing.
        /// </summary>
        internal string ReturnUrl
        {
            get
            {
                return this.returnUrl;
            }
        }

        protected abstract AuthenticateUserDelegate AuthenticateUser { get; set; }

        protected abstract AuthenticateUserSilentlyDelegate AuthenticateUserSilently { get; set; }

        public AccountSession CurrentAccountSession { get; internal set; }

        public async Task AuthenticateRequestAsync(HttpRequestMessage request)
        {
            if (this.CurrentAccountSession == null)
            {
                throw new ServiceException(
                    new Error
                    {
                        Code = OAuthConstants.ErrorCodes.AuthenticationFailure,
                        Message = "Please call one of the AuthenticateUserAsync...() methods to authenticate the user before trying to authenticate a request.",
                    });
            }

            if (this.CurrentAccountSession.IsExpiring)
            {
                if (!string.IsNullOrEmpty(this.CurrentAccountSession.RefreshToken))
                {
                    await this.AuthenticateUserWithRefreshTokenAsync(
                        this.CurrentAccountSession.RefreshToken,
                        this.currentServiceResourceId).ConfigureAwait(false);
                }
                else
                {
                    IAuthenticationResult silentAuthenticationResult = null;

                    var authenticationFailedErrorMessage = "Failed to retrieve a cached account session or silently retrieve a new access token. Please call AuthenticateUserAsync...() again to re-authenticate.";

                    try
                    {
                        silentAuthenticationResult = await this.AuthenticateUserSilently(
                            this.currentServiceResourceId,
                            this.CurrentAccountSession.UserId,
                            true).ConfigureAwait(false);
                    }
                    catch (Exception exception)
                    {
                        
                        throw new ServiceException(
                            new Error
                            {
                                Code = OAuthConstants.ErrorCodes.AuthenticationFailure,
                                Message = authenticationFailedErrorMessage
                            },
                            exception);
                    }

                    this.ValidateAuthenticationResult(silentAuthenticationResult, authenticationFailedErrorMessage);

                    this.CurrentAccountSession = this.ConvertAuthenticationResultToAccountSession(silentAuthenticationResult);
                }
            }

            var accessTokenType = string.IsNullOrEmpty(this.CurrentAccountSession.AccessTokenType)
                ? OAuthConstants.Headers.Bearer
                : this.CurrentAccountSession.AccessTokenType;

            request.Headers.Authorization = new AuthenticationHeaderValue(
                accessTokenType,
                this.CurrentAccountSession.AccessToken);
        }

        public async Task AuthenticateUserAsync(string serviceResourceId, string userId = null)
        {
            if (string.IsNullOrEmpty(serviceResourceId))
            {
                throw new ServiceException(
                    new Error
                    {
                        Code = OAuthConstants.ErrorCodes.AuthenticationFailure,
                        Message = "Service resource ID is required to authenticate a user with AuthenticateUserAsync."
                    });
            }

            this.currentServiceResourceId = serviceResourceId;

            IAuthenticationResult authenticationResult = null;

            try
            {
                authenticationResult = await this.AuthenticateUserSilently(serviceResourceId, userId, false).ConfigureAwait(false);

                this.ValidateAuthenticationResult(authenticationResult);
            }
            catch (Exception)
            {
                // If silent authentication fails swallow the exception and try prompting the user.
                // Reset authenticationResult to null in case we have a failed result object.
                authenticationResult = null;
            }

            if (authenticationResult == null)
            {
                if (string.IsNullOrEmpty(returnUrl))
                {
                    throw new ServiceException(
                        new Error
                        {
                            Code = OAuthConstants.ErrorCodes.AuthenticationFailure,
                            Message = "The user could not be silently authenticated and return URL is required to prompt the user for authentication."
                        });
                }

                try
                {
                    authenticationResult = await this.AuthenticateUser(serviceResourceId, userId).ConfigureAwait(false);
                }
                catch (Exception exception)
                {
                    BusinessAuthenticationExceptionHelper.HandleAuthenticationException(exception);
                }

                if (authenticationResult == null)
                {
                    BusinessAuthenticationExceptionHelper.HandleAuthenticationException(null);
                }
            }

            this.CurrentAccountSession = this.ConvertAuthenticationResultToAccountSession(authenticationResult);
        }

        public abstract Task AuthenticateUserWithRefreshTokenAsync(string refreshToken);

        public abstract Task AuthenticateUserWithRefreshTokenAsync(string refreshToken, string serviceResourceId);

        public Task SignOutAsync()
        {
            this.adalCredentialCache.Clear();
            this.currentServiceResourceId = null;
            this.CurrentAccountSession = null;

            return Task.FromResult(0);
        }

        protected AccountSession ConvertAuthenticationResultToAccountSession(IAuthenticationResult authenticationResult)
        {
            if (authenticationResult == null)
            {
                return null;
            }

            return new AccountSession
            {
                AccessToken = authenticationResult.AccessToken,
                AccessTokenType = authenticationResult.AccessTokenType,
                ClientId = this.clientId,
                ExpiresOnUtc = authenticationResult.ExpiresOn,
                RefreshToken = authenticationResult.RefreshToken,
                UserId = authenticationResult.UserInfo == null ? null : authenticationResult.UserInfo.UniqueId,
            };
        }

        protected UserIdentifier GetUserIdentifierForAuthentication(string userId)
        {
            return string.IsNullOrEmpty(userId)
                ? UserIdentifier.AnyUser
                : new UserIdentifier(userId, UserIdentifierType.OptionalDisplayableId);
        }

        protected virtual void ValidateAuthenticationResult(IAuthenticationResult authenticationResult, string errorMessage = null)
        {
            if (string.IsNullOrEmpty(errorMessage))
            {
                errorMessage = "Failed to retrieve a valid authentication result.";
            }

            if (authenticationResult == null)
            {
                throw new ServiceException(
                    new Error
                    {
                        Code = OAuthConstants.ErrorCodes.AuthenticationFailure,
                        Message = errorMessage,
                    });
            }
        }
    }
}
