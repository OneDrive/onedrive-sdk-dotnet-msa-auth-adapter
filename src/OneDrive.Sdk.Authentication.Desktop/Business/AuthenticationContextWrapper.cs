﻿// ------------------------------------------------------------------------------
//  Copyright (c) 2015 Microsoft Corporation
// 
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
// 
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
// 
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.
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

        /// <summary>
        /// Creates a new AuthenticationContextWrapper instance for the specified <see cref="AuthenticationContext"/>.
        /// </summary>
        /// <param name="authenticationContext">The <see cref="AuthenticationContext"/> to wrap.</param>
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
        /// Authenticates the daemon app silently"/>.
        /// </summary>
        /// <param name="resource">The resource to authenticate against.</param>
        /// <param name="clientCredential">The client credential of the application.</param>
        /// <returns>The <see cref="IAuthenticationResult"/>.</returns>
        public async Task<IAuthenticationResult> AcquireTokenAsyn(string resource, ClientCredential clientCredential)
        {
            var result = await this.authenticationContext.AcquireTokenAsync(resource, clientCredential).ConfigureAwait(false);
            return result == null ? null : new AuthenticationResultWrapper(result);
        }

        /// <summary>
        /// Authenticates the user silently using <see cref="AuthenticationContext.AcquireTokenSilentAsync(string, string, UserIdentifier)"/>.
        /// </summary>
        /// <param name="resource">The resource to authenticate against.</param>
        /// <param name="clientId">The client ID of the application.</param>
        /// <param name="userIdentifier">The <see cref="UserIdentifier"/> of the user.</param>
        /// <returns>The <see cref="IAuthenticationResult"/>.</returns>
        public async Task<IAuthenticationResult> AcquireTokenSilentAsync(string resource, string clientId, UserIdentifier userIdentifier)
        {
            var result = await this.authenticationContext.AcquireTokenSilentAsync(
                resource,
                clientId,
                userIdentifier).ConfigureAwait(false);

            return result == null ? null : new AuthenticationResultWrapper(result);
        }

        /// <summary>
        /// Authenticates the user silently using <see cref="AuthenticationContext.AcquireTokenSilentAsync(string, ClientAssertionCertificate, UserIdentifier)"/>.
        /// </summary>
        /// <param name="resource">The resource to authenticate against.</param>
        /// <param name="clientAssertionCertificate">The client assertion certificate of the application.</param>
        /// <param name="userIdentifier">The <see cref="UserIdentifier"/> of the user.</param>
        /// <returns>The <see cref="IAuthenticationResult"/>.</returns>
        public async Task<IAuthenticationResult> AcquireTokenSilentAsync(
            string resource,
            ClientAssertionCertificate clientAssertionCertificate,
            UserIdentifier userIdentifier)
        {
            var result = await this.authenticationContext.AcquireTokenSilentAsync(
                resource,
                clientAssertionCertificate,
                userIdentifier).ConfigureAwait(false);

            return result == null ? null : new AuthenticationResultWrapper(result);
        }

        /// <summary>
        /// Authenticates the user silently using <see cref="AuthenticationContext.AcquireTokenSilentAsync(string, ClientCredential, UserIdentifier)"/>.
        /// </summary>
        /// <param name="resource">The resource to authenticate against.</param>
        /// <param name="clientCredential">The client credential of the application.</param>
        /// <param name="userIdentifier">The <see cref="UserIdentifier"/> of the user.</param>
        /// <returns>The <see cref="IAuthenticationResult"/>.</returns>
        public async Task<IAuthenticationResult> AcquireTokenSilentAsync(string resource, ClientCredential clientCredential, UserIdentifier userIdentifier)
        {
            var result = await this.authenticationContext.AcquireTokenSilentAsync(
                resource,
                clientCredential,
                userIdentifier).ConfigureAwait(false);

            return result == null ? null : new AuthenticationResultWrapper(result);
        }

        /// <summary>
        /// Authenticates the user using <see cref="AuthenticationContext.AcquireToken(string, string, Uri, PromptBehavior, UserIdentifier)"/>.
        /// </summary>
        /// <param name="resource">The resource to authenticate against.</param>
        /// <param name="clientId">The client ID of the application.</param>
        /// <param name="redirectUri">The redirect URI of the application.</param>
        /// <param name="promptBehavior">The <see cref="PromptBehavior"/> for authentication.</param>
        /// <param name="userIdentifier">The <see cref="UserIdentifier"/> for authentication.</param>
        /// <returns>The <see cref="IAuthenticationResult"/>.</returns>
        public IAuthenticationResult AcquireToken(
            string resource,
            string clientId,
            Uri redirectUri,
            PromptBehavior promptBehavior,
            UserIdentifier userIdentifier)
        {
            var result = this.authenticationContext.AcquireToken(resource, clientId, redirectUri, promptBehavior, userIdentifier);

            return result == null ? null : new AuthenticationResultWrapper(result);
        }

        /// <summary>
        /// Authenticates the user silently using <see cref="AuthenticationContext.AcquireTokenByAuthorizationCodeAsync(string, Uri, ClientCredential, string)"/>.
        /// </summary>
        /// <param name="code">The authorization code.</param>
        /// <param name="redirectUri">The redirect URI for the application.</param>
        /// <param name="clientCredential">The client credential of the application.</param>
        /// <param name="resource">The resource to authenticate against.</param>
        /// <returns>The <see cref="IAuthenticationResult"/>.</returns>
        public async Task<IAuthenticationResult> AcquireTokenByAuthorizationCodeAsync(
            string code,
            Uri redirectUri,
            ClientCredential clientCredential,
            string resource)
        {
            var result = await this.authenticationContext.AcquireTokenByAuthorizationCodeAsync(
                code,
                redirectUri,
                clientCredential,
                resource).ConfigureAwait(false);

            return result == null ? null : new AuthenticationResultWrapper(result);
        }

        /// <summary>
        /// Authenticates the user silently using <see cref="AuthenticationContext.AcquireTokenByAuthorizationCodeAsync(string, Uri, ClientAssertionCertificate, string)"/>.
        /// </summary>
        /// <param name="code">The authorization code.</param>
        /// <param name="redirectUri">The redirect URI for the application.</param>
        /// <param name="clientAssertionCertificate">The client assertion certificate of the application.</param>
        /// <param name="resource">The resource to authenticate against.</param>
        /// <returns>The <see cref="IAuthenticationResult"/>.</returns>
        public async Task<IAuthenticationResult> AcquireTokenByAuthorizationCodeAsync(
            string code,
            Uri redirectUri,
            ClientAssertionCertificate clientAssertionCertificate,
            string resource)
        {
            var result = await this.authenticationContext.AcquireTokenByAuthorizationCodeAsync(
                code,
                redirectUri,
                clientAssertionCertificate,
                resource).ConfigureAwait(false);

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
                resource).ConfigureAwait(false);

            return result == null ? null : new AuthenticationResultWrapper(result);
        }

        /// <summary>
        /// Authenticates the user silently using <see cref="AuthenticationContext.AcquireTokenByRefreshTokenAsync(string, ClientCredential, string)"/>.
        /// </summary>
        /// <param name="refreshToken">The refresh token.</param>
        /// <param name="clientCredential">The client credential of the application.</param>
        /// <param name="resource">The resource to authenticate against.</param>
        /// <returns>The <see cref="IAuthenticationResult"/>.</returns>
        public async Task<IAuthenticationResult> AcquireTokenByRefreshTokenAsync(
            string refreshToken,
            ClientCredential clientCredential,
            string resource)
        {
            var result = await this.authenticationContext.AcquireTokenByRefreshTokenAsync(
                refreshToken,
                clientCredential,
                resource).ConfigureAwait(false);

            return result == null ? null : new AuthenticationResultWrapper(result);
        }

        /// <summary>
        /// Authenticates the user silently using <see cref="AuthenticationContext.AcquireTokenByRefreshTokenAsync(string, ClientAssertionCertificate, string)"/>.
        /// </summary>
        /// <param name="refreshToken">The refresh token.</param>
        /// <param name="clientAssertionCertificate">The client assertion certificate of the application.</param>
        /// <param name="resource">The resource to authenticate against.</param>
        /// <returns>The <see cref="IAuthenticationResult"/>.</returns>
        public async Task<IAuthenticationResult> AcquireTokenByRefreshTokenAsync(
            string refreshToken,
            ClientAssertionCertificate clientAssertionCertificate,
            string resource)
        {
            var result = await this.authenticationContext.AcquireTokenByRefreshTokenAsync(
                refreshToken,
                clientAssertionCertificate,
                resource).ConfigureAwait(false);

            return result == null ? null : new AuthenticationResultWrapper(result);
        }
    }
}
