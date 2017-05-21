// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.OneDrive.Sdk.Authentication
{
    using System;
    using System.Threading.Tasks;

    using Microsoft.IdentityModel.Clients.ActiveDirectory;

    public class AuthenticationContextWrapper : IAuthenticationContextWrapper
    {
        internal AuthenticationContext authenticationContext;
        internal ITokenCache tokenCache;

        public AuthenticationContextWrapper(AuthenticationContext authenticationContext)
        {
            this.authenticationContext = authenticationContext;
        }

        public ITokenCache TokenCache
        {
            get
            {
                if (this.tokenCache == null)
                {
                    this.tokenCache = new TokenCacheWrapper(this.authenticationContext.TokenCache);
                }

                return this.tokenCache;
            }
        }

        /// <summary>
        /// Authenticates the user silently using <see cref="AuthenticationContext.AcquireToken(string, string, UserIdentifier)"/>.
        /// </summary>
        /// <param name="resource">The resource to authenticate against.</param>
        /// <param name="clientId">The client ID of the application.</param>
        /// <param name="userIdentifier">The <see cref="UserIdentifier"/> for authentication.</param>
        /// <returns>The <see cref="IAuthenticationResult"/>.</returns>
        public async Task<IAuthenticationResult> AcquireTokenSilentAsync(string resource, string clientId, UserIdentifier userIdentifier)
        {
            var result = await this.authenticationContext.AcquireTokenSilentAsync(
                resource,
                clientId,
                userIdentifier).AsTask().ConfigureAwait(false);

            return result == null ? null : new AuthenticationResultWrapper(result);
        }

        /// <summary>
        /// Authenticates the user using <see cref="AuthenticationContext.AcquireTokenAsync(string, string, Uri, PromptBehavior, UserIdentifier)"/>.
        /// </summary>
        /// <param name="resource">The resource to authenticate against.</param>
        /// <param name="clientId">The client ID of the application.</param>
        /// <param name="redirectUri">The redirect URI of the application.</param>
        /// <param name="promptBehavior">The <see cref="PromptBehavior"/> for authentication.</param>
        /// <param name="userIdentifier">The <see cref="UserIdentifier"/> for authentication.</param>
        /// <returns>The <see cref="IAuthenticationResult"/>.</returns>
        public async Task<IAuthenticationResult> AcquireTokenAsync(
            string resource,
            string clientId,
            Uri redirectUri,
            PromptBehavior promptBehavior,
            UserIdentifier userIdentifier)
        {
            var result = await this.authenticationContext.AcquireTokenAsync(
                resource,
                clientId,
                redirectUri,
                promptBehavior,
                userIdentifier).AsTask().ConfigureAwait(false);

            return result == null ? null : new AuthenticationResultWrapper(result);
        }

        /// <summary>
        /// Authenticates the user silently using <see cref="AuthenticationContext.AcquireTokenByRefreshToken(string, string, string)"/>.
        /// </summary>
        /// <param name="refreshToken">The refresh token.</param>
        /// <param name="clientId">The client ID for the application.</param>
        /// <param name="resource">The resource to authenticate against.</param>
        /// <returns>The <see cref="IAuthenticationResult"/>.</returns>
        public async Task<IAuthenticationResult> AcquireTokenByRefreshTokenAsync(
            string refreshToken,
            string clientId,
            string resource)
        {
            var result = await this.authenticationContext.AcquireTokenByRefreshTokenAsync(
                refreshToken, 
                clientId,
                resource).AsTask().ConfigureAwait(false);

            return result == null ? null : new AuthenticationResultWrapper(result);
        }
    }
}
