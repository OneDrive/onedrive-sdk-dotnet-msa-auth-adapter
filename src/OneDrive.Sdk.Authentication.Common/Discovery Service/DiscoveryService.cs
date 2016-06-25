// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.OneDrive.Sdk.Authentication
{
    /// <summary>
    /// Class for deserializing discovery service objects returned from calls to the discovery service.
    /// </summary>
    public class DiscoveryService
    {
        /// <summary>
        /// Gets or sets the capability for the service.
        /// </summary>
        public string Capability { get; set; }

        /// <summary>
        /// Gets or sets the service API version.
        /// </summary>
        public string ServiceApiVersion { get; set; }

        /// <summary>
        /// Gets or sets the URL for the service endpoint.
        /// </summary>
        public string ServiceEndpointUri { get; set; }

        /// <summary>
        /// Gets or sets the resource for the service.
        /// </summary>
        public string ServiceResourceId { get; set; }
    }
}
