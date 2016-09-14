// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.OneDrive.Sdk.Authentication
{
    using System;
    using System.Security.Cryptography;

    public class CredentialVault : ICredentialVault
    {
        private static readonly string vaultResourcePrefix = "OneDriveSDK_AuthAdapter";
        private static readonly string vaultNullUserName = "DefaultUser";

        private string clientId { get; set; }
        private string vaultResourceName { get { return CredentialVault.vaultResourcePrefix + this.clientId; } }

        public CredentialVault(string clientId)
        {
            if (string.IsNullOrEmpty(clientId))
            {
                throw new ArgumentException("You must provide a clientId");
            }

            this.clientId = clientId;
        }

        public void AddAccountSessionToVault(AccountSession accountSession)
        {
            throw new NotImplementedException();
        }

        public AccountSession RetrieveAccountSession()
        {
            throw new NotImplementedException();
        }

        public bool DeleteStoredAccountSession()
        {
            throw new NotImplementedException();
        }
    }
}