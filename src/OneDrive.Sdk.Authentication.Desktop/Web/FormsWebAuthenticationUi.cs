// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.OneDrive.Sdk.Authentication
{
    using System;
    using System.Collections.Generic;
    using System.Threading.Tasks;

    public class FormsWebAuthenticationUi : IWebAuthenticationUi
    {
        /// <summary>
        /// Displays authentication UI to the user for the specified request URI, returning
        /// the key value pairs from the query string upon reaching the callback URL.
        /// </summary>
        /// <param name="requestUri">The request URI.</param>
        /// <param name="callbackUri">The callback URI.</param>
        /// <returns>The <see cref="IDictionary{string, string}"/> of key value pairs from the callback URI query string.</returns>
        public async Task<IDictionary<string, string>> AuthenticateAsync(Uri requestUri, Uri callbackUri)
        {
            using (var formsDialog = new FormsWebDialog())
            {
                var responseValues = await formsDialog.GetAuthenticationResponseValues(requestUri, callbackUri);
                return responseValues;
            }
        }
    }
}
