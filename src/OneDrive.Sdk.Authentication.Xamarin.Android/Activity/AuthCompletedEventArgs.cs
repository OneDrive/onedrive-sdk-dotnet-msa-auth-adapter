// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.OneDrive.Sdk.Authentication
{
    using System;
    using System.Collections.Generic;

    public class AuthCompletedEventArgs : EventArgs
    {
        public AuthCompletedEventArgs(IDictionary<string, string> authorizationParameters)
        {
            this.AuthorizationParameters = authorizationParameters;
        }

        public IDictionary<string, string> AuthorizationParameters { get; private set; }
    }
}