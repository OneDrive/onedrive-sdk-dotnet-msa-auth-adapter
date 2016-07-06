// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.OneDrive.Sdk.Authentication
{
    using System;

    public interface IUserInfo
    {
        string DisplayableId { get; }

        string FamilyName { get; }

        string GivenName { get; }

        string IdentityProvider { get; }

        Uri PasswordChangeUrl { get; }

        DateTimeOffset? PasswordExpiresOn { get; }

        string UniqueId { get; }
    }
}
