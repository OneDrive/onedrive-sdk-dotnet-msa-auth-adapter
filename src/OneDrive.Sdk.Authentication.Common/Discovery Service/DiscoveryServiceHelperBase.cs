// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.OneDrive.Sdk.Authentication
{
    using System;
    using System.Linq;
    using System.Net.Http;
    using System.Threading.Tasks;

    using Microsoft.Graph;
    
    public abstract class DiscoveryServiceHelperBase
    {
        protected IAuthenticationProvider authenticationProvider;

        protected DiscoveryServiceHelperBase(IAuthenticationProvider authenticationProvider)
        {
            this.authenticationProvider = authenticationProvider;
        }

        protected async Task<BusinessServiceInformation> RetrieveMyFilesServiceResourceAsync()
        {
            using (var httpProvider = new HttpProvider())
            {
                var businessServiceInfo = await this.RetrieveMyFilesServiceResourceAsync(httpProvider).ConfigureAwait(false);
                return businessServiceInfo;
            }
        }

        protected async Task<BusinessServiceInformation> RetrieveMyFilesServiceResourceAsync(IHttpProvider httpProvider)
        {
            using (var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, OAuthConstants.ActiveDirectoryDiscoveryServiceUrl))
            {
                await this.authenticationProvider.AuthenticateRequestAsync(httpRequestMessage).ConfigureAwait(false);

                using (var response = await httpProvider.SendAsync(httpRequestMessage).ConfigureAwait(false))
                using (var responseStream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false))
                {
                    var responseValues = httpProvider.Serializer.DeserializeObject<DiscoveryServiceResponse>(responseStream);
                    if (responseValues == null || responseValues.Value == null)
                    {
                        throw new ServiceException(
                            new Error
                            {
                                Code = OAuthConstants.ErrorCodes.AuthenticationFailure,
                                Message = "MyFiles capability not found for the current user."
                            });
                    }

                    var service = responseValues.Value.FirstOrDefault(value =>
                        string.Equals(value.ServiceApiVersion, "v2.0", StringComparison.OrdinalIgnoreCase) &&
                        string.Equals(value.Capability, "MyFiles", StringComparison.OrdinalIgnoreCase));

                    if (service == null)
                    {
                        throw new ServiceException(
                            new Error
                            {
                                Code = OAuthConstants.ErrorCodes.AuthenticationFailure,
                                Message = "MyFiles capability with version v2.0 not found for the current user.",
                            });
                    }

                return new BusinessServiceInformation
                {
                    ServiceEndpointBaseUrl = service.ServiceEndpointUri,
                    ServiceResourceId = service.ServiceResourceId,
                };
                }
            }
        }
    }
}
