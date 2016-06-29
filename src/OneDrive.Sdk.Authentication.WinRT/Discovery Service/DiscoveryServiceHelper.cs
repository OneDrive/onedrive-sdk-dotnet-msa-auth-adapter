// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.OneDrive.Sdk.Authentication
{
    using System.Threading.Tasks;

    using Microsoft.Graph;
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

        public async Task<BusinessServiceInformation> DiscoverFilesEndpointInformationForUserAsync(
            string userId = null,
            IHttpProvider httpProvider = null)
        {
            await ((AdalAuthenticationProvider)this.authenticationProvider).AuthenticateUserAsync(
                OAuthConstants.ActiveDirectoryDiscoveryResource,
                userId).ConfigureAwait(false);

            return await this.RetrieveMyFilesInformationAsync(httpProvider).ConfigureAwait(false);
        }

        public async Task<BusinessServiceInformation> DiscoverFilesEndpointInformationForUserWithRefreshTokenAsync(
            string refreshToken,
            IHttpProvider httpProvider = null)
        {
            await ((AdalAuthenticationProvider)this.authenticationProvider).AuthenticateUserWithRefreshTokenAsync(
                refreshToken,
                OAuthConstants.ActiveDirectoryDiscoveryResource).ConfigureAwait(false);

            return await this.RetrieveMyFilesInformationAsync(httpProvider).ConfigureAwait(false);
        }

        private async Task<BusinessServiceInformation> RetrieveMyFilesInformationAsync(IHttpProvider httpProvider)
        {
            BusinessServiceInformation businessServiceInformation = null;

            if (httpProvider == null)
            {
                businessServiceInformation = await this.RetrieveMyFilesServiceResourceAsync().ConfigureAwait(false);
            }
            else
            {
                businessServiceInformation = await this.RetrieveMyFilesServiceResourceAsync(httpProvider).ConfigureAwait(false);
            }

            return businessServiceInformation;
        }
    }
}
