// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.OneDrive.Sdk.Authentication
{
    using System;

    using Microsoft.IdentityModel.Clients.ActiveDirectory;

    public class TokenCacheItemWrapper : ITokenCacheItem
    {
        /// <summary>
        /// Instantiates a new <see cref="TokenCacheItemWrapper"/>.
        /// </summary>
        /// <param name="tokenCacheItem">The <see cref="TokenCacheItem"/> to store as the inner cache item.</param>
        public TokenCacheItemWrapper(TokenCacheItem tokenCacheItem)
        {
            this.InnerCacheItem = tokenCacheItem;
        }

        /// <summary>
        /// Gets the access token.
        /// </summary>
        public string AccessToken
        {
            get
            {
                return this.InnerCacheItem.AccessToken;
            }
        }
        
        /// <summary>
        /// Gets the authority.
        /// </summary>
        public string Authority
        {
            get
            {
                return this.InnerCacheItem.Authority;
            }
        }

        /// <summary>
        /// Gets the client ID.
        /// </summary>
        public string ClientId
        {
            get
            {
                return this.InnerCacheItem.ClientId;
            }
        }

        /// <summary>
        /// Gets the user's displayable ID.
        /// </summary>
        public string DisplayableId
        {
            get
            {
                return this.InnerCacheItem.DisplayableId;
            }
        }

        /// <summary>
        /// Gets the expiration.
        /// </summary>
        public DateTimeOffset ExpiresOn
        {
            get
            {
                return this.InnerCacheItem.ExpiresOn;
            }
        }

        /// <summary>
        /// Gets the family name.
        /// </summary>
        public string FamilyName
        {
            get
            {
                return this.InnerCacheItem.FamilyName;
            }
        }

        /// <summary>
        /// Gets the given name.
        /// </summary>
        public string GivenName
        {
            get
            {
                return this.InnerCacheItem.GivenName;
            }
        }

        /// <summary>
        /// Gets the identity provider name.
        /// </summary>
        public string IdentityProvider
        {
            get
            {
                return this.InnerCacheItem.IdentityProvider;
            }
        }

        /// <summary>
        /// Gets the entire ID token if returned by the service or null if no ID token is returned.
        /// </summary>
        public string IdToken
        {
            get
            {
                return this.InnerCacheItem.IdToken;
            }
        }

        /// <summary>
        /// Gets the inner <see cref="TokenCacheItem"/>.
        /// </summary>
        public TokenCacheItem InnerCacheItem { get; private set; }

        /// <summary>
        /// Gets a value indicating whether or not the refresh token applies to multiple resources.
        /// </summary>
        public bool IsMultipleResourceRefreshToken
        {
            get
            {
                return this.InnerCacheItem.IsMultipleResourceRefreshToken;
            }
        }

        /// <summary>
        /// Gets the refresh token associated with the requested access token. Note: not
        /// all operations will return a refresh token.
        /// </summary>
        public string RefreshToken
        {
            get
            {
                return this.InnerCacheItem.RefreshToken;
            }
        }

        /// <summary>
        /// Gets the resource.
        /// </summary>
        public string Resource
        {
            get
            {
                return this.InnerCacheItem.Resource;
            }
        }

        /// <summary>
        /// Get's the user's tenant ID.
        /// </summary>
        public string TenantId
        {
            get
            {
                return this.InnerCacheItem.TenantId;
            }
        }

        /// <summary>
        /// Gets the user's unique ID.
        /// </summary>
        public string UniqueId
        {
            get
            {
                return this.InnerCacheItem.UniqueId;
            }
        }
    }
}
