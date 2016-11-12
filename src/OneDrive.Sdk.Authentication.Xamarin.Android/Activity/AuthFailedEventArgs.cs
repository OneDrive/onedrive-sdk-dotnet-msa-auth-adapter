// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.OneDrive.Sdk.Authentication
{
    using System;

    public class AuthFailedEventArgs : EventArgs
    {
        public AuthFailedEventArgs(Exception error)
        {
            this.Error = error;
        }

        public Exception Error { get; private set; }
    }
}