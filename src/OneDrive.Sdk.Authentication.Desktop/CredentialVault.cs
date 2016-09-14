// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.OneDrive.Sdk.Authentication
{
    using System;
    using System.Security.Cryptography;

    public class CredentialVault : ICredentialVault
    {
        public void AddAccountSessionToVault(AccountSession accountSession)
        {
            throw new NotImplementedException();
        }

        public AccountSession RetrieveAccountSession(string clientId, string userId = null)
        {
            throw new NotImplementedException();
        }
    }
}