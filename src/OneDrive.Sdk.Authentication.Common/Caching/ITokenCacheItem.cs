// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.OneDrive.Sdk.Authentication
{
    using System;

    using Microsoft.IdentityModel.Clients.ActiveDirectory;

    public interface ITokenCacheItem
    {
        /// <summary>
        /// Gets the access token.
        /// </summary>
        string AccessToken { get; }

        /// <summary>
        /// Gets the authority.
        /// </summary>
        string Authority { get; }

        /// <summary>
        /// Gets the client ID.
        /// </summary>
        string ClientId { get; }

        /// <summary>
        /// Gets the user's displayable ID.
        /// </summary>
        string DisplayableId { get; }

        /// <summary>
        /// Gets the expiration.
        /// </summary>
        DateTimeOffset ExpiresOn { get; }

        /// <summary>
        /// Gets the family name.
        /// </summary>
        string FamilyName { get; }

        /// <summary>
        /// Gets the given name.
        /// </summary>
        string GivenName { get; }

        /// <summary>
        /// Gets the identity provider name.
        /// </summary>
        string IdentityProvider { get; }

        /// <summary>
        /// Gets the entire ID token if returned by the service or null if no ID token is returned.
        /// </summary>
        string IdToken { get; }

        /// <summary>
        /// Gets the inner <see cref="TokenCacheItem"/>.
        /// </summary>
        TokenCacheItem InnerCacheItem { get; }

        /// <summary>
        /// Gets a value indicating whether or not the refresh token applies to multiple resources.
        /// </summary>
        bool IsMultipleResourceRefreshToken { get; }

        /// <summary>
        /// Gets the refresh token associated with the requested access token. Note: not
        /// all operations will return a refresh token.
        /// </summary>
        string RefreshToken { get; }

        /// <summary>
        /// Gets the resource.
        /// </summary>
        string Resource { get; }

        /// <summary>
        /// Get's the user's tenant ID.
        /// </summary>
        string TenantId { get; }

        /// <summary>
        /// Gets the user's unique ID.
        /// </summary>
        string UniqueId { get; }
    }
}