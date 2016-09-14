// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.OneDrive.Sdk.Authentication
{
    using Windows.Security.Credentials;

    public class CredentialVault : ICredentialVault
    {
        private static readonly string vaultResourceName = "OneDriveSDK_AuthAdapter";
        private static readonly string vaultNullUserName = "DefaultUser";

        public void AddAccountSessionToVault(AccountSession accountSession)
        {
            var vault = new PasswordVault();
            var userName = CredentialVault.BuildUserName(accountSession.ClientId, accountSession.UserId);
            var cred = new PasswordCredential(CredentialVault.vaultResourceName, userName, accountSession.RefreshToken);
            vault.Add(cred);
        }

        public AccountSession RetrieveAccountSession(string clientId, string userId = null)
        {
            var vault = new PasswordVault();
            var cred = vault.Retrieve(CredentialVault.vaultResourceName, CredentialVault.BuildUserName(clientId, userId));

            if (cred != null)
            {
                return new AccountSession
                    {
                        ClientId = clientId,
                        RefreshToken = cred.Password
                    };
            }
            else
            {
                return null;
            }
        }

        private static string BuildUserName(string clientId, string userId = null)
        {
            return clientId + userId ?? CredentialVault.vaultNullUserName;
        }
    }
}
