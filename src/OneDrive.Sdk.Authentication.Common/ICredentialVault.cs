// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.OneDrive.Sdk.Authentication
{
    public interface ICredentialVault
    {
        /// <summary>
        /// Store the CredentialCache somewhere safe. If anything was previously
        /// stored in this vault, it is deleted.
        /// </summary>
        /// <param name="credentialCache">The cache to be serialized and stored.</param>
        void AddCredentialCacheToVault(CredentialCache credentialCache);

        /// <summary>
        /// Retrieve the cache information and store it in <paramref name="credentialCache"/>
        /// </summary>
        /// <param name="credentialCache">Place to store the retrieved credentials.</param>
        /// <returns>True if the cache was successfully retrieved, otherwise false.</returns>
        bool RetrieveCredentialCache(CredentialCache credentialCache);

        /// <summary>
        /// Clear out stored credentials.
        /// </summary>
        /// <returns>True if the credentials were cleared, otherwise false.</returns>
        bool DeleteStoredCredentialCache();
    }
}
