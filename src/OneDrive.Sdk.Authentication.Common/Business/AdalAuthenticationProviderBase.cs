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
        protected delegate Task<AuthenticationResult> AuthenticateUserDelegate(string serviceResourceId, string userId);
        protected delegate Task<AuthenticationResult> AuthenticateUserSilentlyDelegate(string serviceResourceId, string userId);

        protected readonly string clientId;
        protected readonly string returnUrl;
        protected string currentServiceResourceId;

        protected AuthenticationContext authenticationContext;

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

            if (string.IsNullOrEmpty(returnUrl))
            {
                throw new ServiceException(
                    new Error
                    {
                        Code = OAuthConstants.ErrorCodes.AuthenticationFailure,
                        Message = "AdalAuthenticationProvider requires a return URL for authenticating users."
                    });
            }

            this.clientId = clientId;
            this.returnUrl = returnUrl;
            this.authenticationContext = authenticationContext ?? new AuthenticationContext(OAuthConstants.ActiveDirectoryAuthenticationServiceUrl);
        }

        protected abstract AuthenticateUserDelegate AuthenticateUser { get; set; }

        protected abstract AuthenticateUserSilentlyDelegate AuthenticateUserSilently { get; set; }

        public AuthenticationResult CurrentAuthenticationResult { get; protected set; }

        public async Task AuthenticateRequestAsync(HttpRequestMessage request)
        {
            if (this.CurrentAuthenticationResult == null)
            {
                throw new ServiceException(
                    new Error
                    {
                        Code = OAuthConstants.ErrorCodes.AuthenticationFailure,
                        Message = "Please call one of the AuthenticateUserAsync...() methods to authenticate the user before trying to authenticate a request.",
                    });
            }

            if (this.IsExpiring(this.CurrentAuthenticationResult))
            {
                if (!string.IsNullOrEmpty(this.CurrentAuthenticationResult.RefreshToken))
                {
                    await this.AuthenticateUserWithRefreshTokenAsync(
                        this.CurrentAuthenticationResult.RefreshToken,
                        this.currentServiceResourceId).ConfigureAwait(false);
                }
                else
                {
                    AuthenticationResult silentAuthenticationResult = null;

                    try
                    {
                        silentAuthenticationResult = await this.AuthenticateUserSilently(
                            this.currentServiceResourceId,
                            this.CurrentAuthenticationResult.UserInfo == null
                                ? null
                                : this.CurrentAuthenticationResult.UserInfo.UniqueId).ConfigureAwait(false);
                    }
                    catch (Exception exception)
                    {
                        throw new ServiceException(
                            new Error
                            {
                                Code = OAuthConstants.ErrorCodes.AuthenticationFailure,
                                Message = "Failed to retrieve a cached account session or silently retrieve a new access token. Please call AuthenticateUserAsync...() again to re-authenticate."
                            },
                            exception);
                    }

                    this.ValidateAuthenticationResult(silentAuthenticationResult);

                    this.CurrentAuthenticationResult = silentAuthenticationResult;
                }
            }

            var accessTokenType = string.IsNullOrEmpty(this.CurrentAuthenticationResult.AccessTokenType)
                ? "bearer"
                : this.CurrentAuthenticationResult.AccessTokenType;

            request.Headers.Authorization = new AuthenticationHeaderValue(
                accessTokenType,
                this.CurrentAuthenticationResult.AccessToken);
        }

        public async Task AuthenticateUserAsync(string serviceResourceId, string userId = null)
        {
            if (string.IsNullOrEmpty(serviceResourceId))
            {
                throw new ServiceException(
                    new Error
                    {
                        Code = OAuthConstants.ErrorCodes.AuthenticationFailure,
                        Message = "Service resource ID is required to authenticate a user."
                    });
            }

            this.currentServiceResourceId = serviceResourceId;

            AuthenticationResult authenticationResult = null;

            try
            {
                authenticationResult = await this.AuthenticateUserSilently(serviceResourceId, userId).ConfigureAwait(false);

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

            this.CurrentAuthenticationResult = authenticationResult;
        }

        public abstract Task AuthenticateUserWithRefreshTokenAsync(string refreshToken);

        public abstract Task AuthenticateUserWithRefreshTokenAsync(string refreshToken, string serviceResourceId);

        public void SignOut()
        {
            this.authenticationContext.TokenCache.Clear();
        }

        protected UserIdentifier GetUserIdentifierForAuthentication(string userId)
        {
            return string.IsNullOrEmpty(userId)
                ? UserIdentifier.AnyUser
                : new UserIdentifier(userId, UserIdentifierType.OptionalDisplayableId);
        }

        protected bool IsExpiring(AuthenticationResult authenticationResult)
        {
            return authenticationResult != null && authenticationResult.ExpiresOn >= DateTimeOffset.UtcNow.AddMinutes(5);
        }

        protected virtual void ValidateAuthenticationResult(AuthenticationResult authenticationResult)
        {
            if (authenticationResult == null)
            {
                throw new ServiceException(
                    new Error
                    {
                        Code = OAuthConstants.ErrorCodes.AuthenticationFailure,
                        Message = "Failed to retrieve a valid authentication result.",
                    });
            }
        }
    }
}
