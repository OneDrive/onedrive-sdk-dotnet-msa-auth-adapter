// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.OneDrive.Sdk.Authentication
{
    using System.Collections.Generic;

    using Microsoft.IdentityModel.Clients.ActiveDirectory;
    using static Microsoft.IdentityModel.Clients.ActiveDirectory.TokenCache;

    public interface ITokenCache
    {
        /// <summary>
        /// Gets or sets the notification delegate for after accessing the cache.
        /// </summary>
        TokenCacheNotification AfterAccess { get; set; }

        /// <summary>
        /// Gets or sets the notification delegate for before accessing the cache.
        /// </summary>
        TokenCacheNotification BeforeAccess { get; set; }

        /// <summary>
        /// Gets or sets the notification delegate for before writing to the cache.
        /// </summary>
        TokenCacheNotification BeforeWrite { get; set; }

        /// <summary>
        /// Gets or sets whether or not the cache state has changed.
        /// </summary>
        bool HasStateChanged { get; set; }

        /// <summary>
        /// Gets the inner <see cref="TokenCache"/>.
        /// </summary>
        TokenCache InnerTokenCache { get; }

        /// <summary>
        /// Clears the cache contents.
        /// </summary>
        void Clear();

        /// <summary>
        /// Deletes the specified <see cref="ITokenCacheItem"/> from the cache.
        /// </summary>
        /// <param name="tokenCacheItem">The <see cref="ITokenCacheItem"/> to delete.</param>
        void DeleteItem(ITokenCacheItem tokenCacheItem);

        /// <summary>
        /// Initializes the cache from the specified contents.
        /// </summary>
        /// <param name="blob">The cache contents.</param>
        void Deserialize(byte[] blob);

        /// <summary>
        /// Returns the collection of <see cref="ITokenCacheItem"/>s in the cache.
        /// </summary>
        /// <returns>The collection of <see cref="ITokenCacheItem"/>s.</returns>
        IEnumerable<ITokenCacheItem> ReadItems();

        /// <summary>
        /// Gets the contents of the cache.
        /// </summary>
        /// <returns>The cache contents.</returns>
        byte[] Serialize();
    }
}
