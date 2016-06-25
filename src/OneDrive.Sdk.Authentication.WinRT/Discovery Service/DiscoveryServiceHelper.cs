// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.OneDrive.Sdk.Authentication
{
    using System.Threading.Tasks;
    
    using Microsoft.IdentityModel.Clients.ActiveDirectory;
    
    public class DiscoveryServiceHelper : DiscoveryServiceHelperBase
    {
        public DiscoveryServiceHelper(
            string clientId,
            string returnUrl,
            AuthenticationContext authenticationContext = null)
            : base(new AdalAuthenticationProvider(clientId, returnUrl, authenticationContext))
        {
        }

        public DiscoveryServiceHelper(AdalAuthenticationProvider adalAuthenticationProvider)
            : base(adalAuthenticationProvider)
        {
        }

        public async Task<BusinessServiceInfo> DiscoverFilesEndpointForUserAsync(string userId = null)
        {
            await ((AdalAuthenticationProvider)this.authenticationProvider).AuthenticateUserAsync(
                OAuthConstants.ActiveDirectoryDiscoveryResource,
                userId).ConfigureAwait(false);

            var businessServiceInfo = await this.RetrieveMyFilesServiceResourceAsync().ConfigureAwait(false);

            return businessServiceInfo;
        }

        public async Task<BusinessServiceInfo> DiscoverFilesEndpointForUserWithRefreshTokenAsync(string refreshToken)
        {
            await ((AdalAuthenticationProvider)this.authenticationProvider).AuthenticateUserWithRefreshTokenAsync(
                refreshToken,
                OAuthConstants.ActiveDirectoryDiscoveryResource).ConfigureAwait(false);

            var businessServiceInfo = await this.RetrieveMyFilesServiceResourceAsync().ConfigureAwait(false);

            return businessServiceInfo;
        }
    }
}
