// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.OneDrive.Sdk.Authentication
{
    public interface ICredentialVault
    {
        void AddAccountSessionToVault(AccountSession accountSession);

        AccountSession RetrieveAccountSession();

        bool DeleteStoredAccountSession();
    }
}
