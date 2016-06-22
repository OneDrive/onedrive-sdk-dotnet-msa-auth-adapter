// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.OneDrive.Sdk.Authentication
{
    using System;

    public class CredentialCacheKey
    {
        private const string Delimiter = ";";

        public string ClientId { get; set; }

        public string UserId { get; set; }

        public override bool Equals(object obj)
        {
            var credentialCacheKey = obj as CredentialCacheKey;

            return credentialCacheKey != null && credentialCacheKey.GetHashCode() == this.GetHashCode();
        }

        public override int GetHashCode()
        {
            return
                (string.Join(
                    CredentialCacheKey.Delimiter,
                    this.ClientId,
                    this.UserId).ToLowerInvariant()).GetHashCode();
        }
    }
}
