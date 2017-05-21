// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.OneDrive.Sdk.Authentication
{
    using System;
    using System.Threading.Tasks;

    using Microsoft.Graph;
    using Microsoft.IdentityModel.Clients.ActiveDirectory;
    
    public class AdalAuthenticationProvider : AdalAuthenticationProviderBase
    {
        public AdalAuthenticationProvider(
            string clientId,
            string returnUrl,
            AuthenticationContext authenticationContext = null)
            : base (clientId, returnUrl, authenticationContext)
        {
            this.AuthenticateUser = this.PromptUserForAuthenticationAsync;
            this.AuthenticateUserSilently = this.SilentlyAuthenticateUserAsync;
        }

        protected override AuthenticateUserDelegate AuthenticateUser { get; set; }

        protected override AuthenticateUserSilentlyDelegate AuthenticateUserSilently { get; set; }

        internal async Task<IAuthenticationResult> SilentlyAuthenticateUserAsync(
            string serviceResourceId,
            string userId,
            bool throwOnError)
        {
            IAuthenticationResult authenticationResult = null;

            try
            {
                authenticationResult = await this.authenticationContextWrapper.AcquireTokenSilentAsync(
                    serviceResourceId,
                    this.clientId,
                    this.GetUserIdentifierForAuthentication(userId)).ConfigureAwait(false);
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

        internal async Task<IAuthenticationResult> PromptUserForAuthenticationAsync(
            string serviceResourceId,
            string userId)
        {
            var authenticationResult = await this.authenticationContextWrapper.AcquireTokenAsync(
                serviceResourceId,
                this.clientId,
                new Uri(this.returnUrl),
                PromptBehavior.Auto,
                this.GetUserIdentifierForAuthentication(userId)).ConfigureAwait(false);

            this.ValidateAuthenticationResult(authenticationResult);

            return authenticationResult;
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

            var authenticationResult = await this.authenticationContextWrapper.AcquireTokenByRefreshTokenAsync(
                refreshToken,
                this.clientId,
                serviceResourceId).ConfigureAwait(false);

            this.ValidateAuthenticationResult(authenticationResult);

            this.CurrentAccountSession = this.ConvertAuthenticationResultToAccountSession(authenticationResult);
        }

        protected override void ValidateAuthenticationResult(IAuthenticationResult authenticationResult, string errorMessage = null)
        {
            if (authenticationResult == null || authenticationResult.Status != AuthenticationStatus.Success)
            {
                if (string.IsNullOrEmpty(errorMessage))
                {
                    errorMessage = "Failed to retrieve a valid authentication result.";
                }

                var innerException = new Exception(authenticationResult.ErrorDescription);
                throw new ServiceException(
                    new Error
                    {
                        Code = OAuthConstants.ErrorCodes.AuthenticationFailure,
                        Message = errorMessage,
                    },
                    innerException);
            }
        }
    }
}
