// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  
//  Licensed under the MIT License.  
//  See License in the project root for license information.
// ------------------------------------------------------------------------------
using System;
using System.Threading.Tasks;
using Microsoft.Graph;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Globalization;
using System.Threading;

namespace Microsoft.OneDrive.Sdk.Authentication.Business
{
    public class AdalDaemonAuthenticationProvider : AdalAuthenticationProviderBase
    {
        private const int _retryCount = 3;
        private const int _retrySleepDuration = 3000;
        protected string _clientId;
        protected string _clientKey;

        public IAuthenticationContextWrapper authContextWrapper;
        protected ClientCredential clientCredential;

        protected override AuthenticateUserDelegate AuthenticateUser { get; set; }
        protected override AuthenticateUserSilentlyDelegate AuthenticateUserSilently { get; set; }

        /// <summary>
        /// Authenticates the user silently 
        /// </summary>
        /// <param name="clientId">Your Application ID</param>
        /// <param name="clientSecret">Your Application Key</param>
        /// <param name="tenant">is usually a domain name for your Office365 service. Like 'yourcompany.onmicrosoft.com'</param>
        public AdalDaemonAuthenticationProvider(
            string clientId,
            string returnUrl,
            string clientSecret,
            string tenant,
            IAuthenticationContextWrapper authenticationContextWrapper) : base(clientId, returnUrl, authenticationContextWrapper)
        {
            _clientId = clientId;
            _clientKey = clientSecret;

            string authority = String.Format(CultureInfo.InvariantCulture, "https://login.microsoftonline.com/{0}", tenant);
            this.authContextWrapper = authenticationContextWrapper;
            this.clientCredential = new ClientCredential(_clientId, _clientKey);

            this.AuthenticateUser = this.PromptUserForAuthenticationAsync;
            this.AuthenticateUserSilently = this.SilentlyAuthenticateUserAsync;
        }

        public async Task AuthenticateUserAsync(string serviceResourceId)
        {
            IAuthenticationResult result = null;
            
            int retryCount = 0;
            bool retry = false;
            this.currentServiceResourceId = serviceResourceId;
            do
            {
                retry = false;
                try
                {
                    result = await this.authContextWrapper.AcquireTokenAsync(
                        serviceResourceId,
                        this.clientCredential);
                }
                catch (AdalException ex)
                {
                    if (ex.ErrorCode == "temporarily_unavailable")
                    {
                        retry = true;
                        retryCount++;
                        await Task.Delay(_retrySleepDuration);
                    }
                }

            } while ((retry == true) && (retryCount < _retryCount));

            this.CurrentAccountSession = this.ConvertAuthenticationResultToAccountSession(result);
        }

        public override Task AuthenticateUserWithRefreshTokenAsync(string refreshToken)
        {
            return this.AuthenticateUserWithRefreshTokenAsync(refreshToken, /* serviceResourceId */ null);
        }

        public override async Task AuthenticateUserWithRefreshTokenAsync(string refreshToken, string serviceResourceId)
        {
            // Daemon App doesn't have refresh token.
            // So we do the authentication again.
            await this.AuthenticateUserAsync(this.currentServiceResourceId);
        }

        private async Task<IAuthenticationResult> SilentlyAuthenticateUserAsync(
            string serviceResourceId,
            string userId,
            bool throwOnError)
        {
            var result = await this.authContextWrapper.AcquireTokenAsync(
                        serviceResourceId,
                        this.clientCredential);
            return result;
        }

        private Task<IAuthenticationResult> PromptUserForAuthenticationAsync(string serviceResourceId, string userId)
        {
            return this.SilentlyAuthenticateUserAsync(
                        serviceResourceId,
                        userId,
                        true);
        }
    }
}


