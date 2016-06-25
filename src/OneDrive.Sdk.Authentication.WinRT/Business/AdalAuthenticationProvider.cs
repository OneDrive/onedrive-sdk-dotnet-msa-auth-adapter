// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.OneDrive.Sdk.Authentication
{
    using System;
    using System.Collections.Generic;
    using System.Net.Http.Headers;
    using System.Linq;
    using System.Net;
    using System.Net.Http;
    using System.Text;
    using System.Threading.Tasks;

    using Microsoft.Graph;
    using Microsoft.IdentityModel.Clients.ActiveDirectory;
    
    public class AdalAuthenticationProvider : AdalAuthenticationProviderBase
    {
        public AdalAuthenticationProvider(
            string clientId,
            string returnUrl)
            : this(clientId, returnUrl, null)
        {
        }

        public AdalAuthenticationProvider(
            string clientId,
            string returnUrl,
            AuthenticationContext authenticationContext)
            : base (clientId, returnUrl, authenticationContext)
        {
            this.AuthenticateUser = this.PromptUserForAuthenticationAsync;
            this.AuthenticateUserSilently = this.SilentlyAuthenticateUserAsync;
        }

        protected override AuthenticateUserDelegate AuthenticateUser { get; set; }

        protected override AuthenticateUserSilentlyDelegate AuthenticateUserSilently { get; set; }

        internal async Task<AuthenticationResult> SilentlyAuthenticateUserAsync(string serviceResourceId, string userId)
        {
            AuthenticationResult authenticationResult = null;

            try
            {
                authenticationResult = await this.authenticationContext.AcquireTokenSilentAsync(
                    OAuthConstants.ActiveDirectoryDiscoveryResource,
                    this.clientId,
                    this.GetUserIdentifierForAuthentication(userId)).AsTask().ConfigureAwait(false);
            }
            catch (Exception)
            {
                // If an exception happens during silent authentication try interactive authentication.
            }

            return authenticationResult;
        }

        internal async Task<AuthenticationResult> PromptUserForAuthenticationAsync(
            string serviceResourceId,
            string userId)
        {
            var authenticationResult = await this.authenticationContext.AcquireTokenAsync(
                serviceResourceId,
                this.clientId,
                new Uri(this.returnUrl),
                PromptBehavior.Auto);

            this.ValidateAuthenticationResult(authenticationResult);

            return authenticationResult;
        }

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

            var authenticationResult = await this.authenticationContext.AcquireTokenByRefreshTokenAsync(refreshToken, this.clientId);

            this.ValidateAuthenticationResult(authenticationResult);

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

            var authenticationResult = await this.authenticationContext.AcquireTokenByRefreshTokenAsync(
                refreshToken,
                this.clientId,
                serviceResourceId);

            this.ValidateAuthenticationResult(authenticationResult);

            this.CurrentAuthenticationResult = authenticationResult;
        }

        protected override void ValidateAuthenticationResult(AuthenticationResult authenticationResult)
        {
            if (authenticationResult == null || authenticationResult.Status != AuthenticationStatus.Success)
            {
                throw new ServiceException(
                    new Error
                    {
                        Code = OAuthConstants.ErrorCodes.AuthenticationFailure,
                        Message = authenticationResult.ErrorDescription,
                    });
            }
        }
    }
}
