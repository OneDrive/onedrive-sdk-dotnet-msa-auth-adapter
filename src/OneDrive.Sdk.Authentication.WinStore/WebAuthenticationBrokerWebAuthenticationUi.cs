// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.OneDrive.Sdk.Authentication
{
    using System;
    using System.Collections.Generic;
    using System.Threading.Tasks;

    using Microsoft.Graph;
    using Windows.Security.Authentication.Web;

    public class WebAuthenticationBrokerWebAuthenticationUi : IWebAuthenticationUi
    {
        /// <summary>
        /// Displays authentication UI to the user for the specified request URI, returning
        /// the key value pairs from the query string upon reaching the callback URL.
        /// </summary>
        /// <param name="requestUri">The request URI.</param>
        /// <param name="callbackUri">The callback URI.</param>
        /// <returns>The <see cref="IDictionary{string, string}"/> of key value pairs from the callback URI query string.</returns>
        public async Task<IDictionary<string, string>> AuthenticateAsync(Uri requestUri, Uri callbackUri = null)
        {
            WebAuthenticationResult result = null;

            // Attempt to authentication without prompting the user first.
            try
            {
                result = await this.AuthenticateAsync(requestUri, callbackUri, WebAuthenticationOptions.SilentMode);
            }
            catch (Exception)
            {
                // WebAuthenticationBroker can throw an exception in silent authentication mode when not using SSO and
                // silent authentication isn't available. Swallow it and try authenticating with user prompt. Even if
                // the exception is another type of exception we'll swallow and try again with the user prompt.
            }

            // AuthenticateAsync will return a UserCancel status in SSO mode if authentication requires user input. Try
            // authentication again using the user prompt flow.
            if (result == null || result.ResponseStatus == WebAuthenticationStatus.UserCancel)
            {
                try
                {
                    result = await this.AuthenticateAsync(requestUri, callbackUri, WebAuthenticationOptions.None);
                }
                catch (Exception exception)
                {
                    throw new ServiceException(new Error { Code = OAuthConstants.ErrorCodes.AuthenticationFailure }, exception);
                }
            }

            if (result != null && !string.IsNullOrEmpty(result.ResponseData))
            {
                return UrlHelper.GetQueryOptions(new Uri(result.ResponseData));
            }
            else if (result != null && result.ResponseStatus == WebAuthenticationStatus.UserCancel)
            {
                throw new ServiceException(new Error { Code = OAuthConstants.ErrorCodes.AuthenticationCanceled });
            }

            throw new ServiceException(new Error { Code = OAuthConstants.ErrorCodes.AuthenticationCanceled });
        }

        private async Task<WebAuthenticationResult> AuthenticateAsync(Uri requestUri, Uri callbackUri, WebAuthenticationOptions authenticationOptions)
        {
            return callbackUri == null
                ? await WebAuthenticationBroker.AuthenticateAsync(authenticationOptions, requestUri)
                : await WebAuthenticationBroker.AuthenticateAsync(authenticationOptions, requestUri, callbackUri);
        }
    }
}
