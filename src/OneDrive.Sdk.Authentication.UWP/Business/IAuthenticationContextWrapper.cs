// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.OneDrive.Sdk.Authentication
{
    using IdentityModel.Clients.ActiveDirectory;
    using System;
    using System.Threading.Tasks;

    public interface IAuthenticationContextWrapper
    {
        ITokenCache TokenCache { get; }

        /// <summary>
        /// Authenticates the user silently using <see cref="AuthenticationContext.AcquireToken(string, string, UserIdentifier)"/>.
        /// </summary>
        /// <param name="resource">The resource to authenticate against.</param>
        /// <param name="clientId">The client ID of the application.</param>
        /// <param name="userIdentifier">The <see cref="UserIdentifier"/> for authentication.</param>
        /// <returns>The <see cref="IAuthenticationResult"/>.</returns>
        Task<IAuthenticationResult> AcquireTokenSilentAsync(string resource, string clientId, UserIdentifier userIdentifier);

        /// <summary>
        /// Authenticates the user using <see cref="AuthenticationContext.AcquireTokenAsync(string, string, Uri, PromptBehavior, UserIdentifier)"/>.
        /// </summary>
        /// <param name="resource">The resource to authenticate against.</param>
        /// <param name="clientId">The client ID of the application.</param>
        /// <param name="redirectUri">The redirect URI of the application.</param>
        /// <param name="promptBehavior">The <see cref="PromptBehavior"/> for authentication.</param>
        /// <param name="userIdentifier">The <see cref="UserIdentifier"/> for authentication.</param>
        /// <returns>The <see cref="IAuthenticationResult"/>.</returns>
        Task<IAuthenticationResult> AcquireTokenAsync(
            string resource,
            string clientId,
            Uri redirectUri,
            PromptBehavior promptBehavior,
            UserIdentifier userIdentifier);

        /// <summary>
        /// Authenticates the user silently using <see cref="AuthenticationContext.AcquireTokenByRefreshToken(string, string, string)"/>.
        /// </summary>
        /// <param name="refreshToken">The refresh token.</param>
        /// <param name="clientId">The client ID for the application.</param>
        /// <param name="resource">The resource to authenticate against.</param>
        /// <returns>The <see cref="IAuthenticationResult"/>.</returns>
        Task<IAuthenticationResult> AcquireTokenByRefreshTokenAsync(
            string refreshToken,
            string clientId,
            string resource);
    }
}
