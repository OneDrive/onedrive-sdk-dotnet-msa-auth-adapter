// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.OneDrive.Sdk.Authentication
{
    using System.Collections.Generic;

    /// <summary>
    /// Class for deserializing responses from the discovery service.
    /// </summary>
    public class DiscoveryServiceResponse
    {
        /// <summary>
        /// The list of <see cref="DiscoveryService"/> objects returned from the discovery service.
        /// </summary>
        public IEnumerable<DiscoveryService> Value { get; set; }
    }
}
