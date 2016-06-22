// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.OneDrive.Sdk.Authentication
{
    using System.Net;
    using System.Text;

    public class OAuthRequestStringBuilder : IOAuthRequestStringBuilder
    {
        /// <summary>
        /// Gets the request URL for OAuth authentication using the code flow.
        /// </summary>
        /// <param name="appId">The ID of the application.</param>
        /// <param name="returnUrl">The return URL for the request. Defaults to the service info value.</param>
        /// <returns>The OAuth request URL.</returns>
        public string GetAuthorizationCodeRequestUrl(string appId, string returnUrl, string[] scopes, string userId = null)
        {
            var requestUriStringBuilder = new StringBuilder();
            requestUriStringBuilder.Append(OAuthConstants.MicrosoftAccountAuthenticationServiceUrl);
            requestUriStringBuilder.AppendFormat("?{0}={1}", OAuthConstants.RedirectUriKeyName, returnUrl);
            requestUriStringBuilder.AppendFormat("&{0}={1}", OAuthConstants.ClientIdKeyName, appId);

            if (scopes != null)
            {
                requestUriStringBuilder.AppendFormat("&{0}={1}", OAuthConstants.ScopeKeyName, WebUtility.UrlEncode(string.Join(" ", scopes)));
            }

            if (!string.IsNullOrEmpty(userId))
            {
                requestUriStringBuilder.AppendFormat("&{0}={1}", OAuthConstants.UserIdKeyName, userId);
            }

            requestUriStringBuilder.AppendFormat("&{0}={1}", OAuthConstants.ResponseTypeKeyName, OAuthConstants.CodeKeyName);

            return requestUriStringBuilder.ToString();
        }

        /// <summary>
        /// Gets the request body for redeeming an authorization code for an access token.
        /// </summary>
        /// <param name="code">The authorization code to redeem.</param>
        /// <param name="appId">The ID of the application.</param>
        /// <param name="returnUrl">The return URL for the request. Defaults to the service info value.</param>
        /// <returns>The request body for the code redemption call.</returns>
        public string GetCodeRedemptionRequestBody(string code, string appId, string returnUrl, string[] scopes, string clientSecret = null)
        {
            var requestBodyStringBuilder = new StringBuilder();
            requestBodyStringBuilder.AppendFormat("{0}={1}", OAuthConstants.RedirectUriKeyName, returnUrl);
            requestBodyStringBuilder.AppendFormat("&{0}={1}", OAuthConstants.ClientIdKeyName, appId);

            if (scopes != null)
            {
                requestBodyStringBuilder.AppendFormat("&{0}={1}", OAuthConstants.ScopeKeyName, WebUtility.UrlEncode(string.Join(" ", scopes)));
            }

            requestBodyStringBuilder.AppendFormat("&{0}={1}", OAuthConstants.CodeKeyName, code);
            requestBodyStringBuilder.AppendFormat("&{0}={1}", OAuthConstants.GrantTypeKeyName, OAuthConstants.AuthorizationCodeGrantType);

            if (!string.IsNullOrEmpty(clientSecret))
            {
                requestBodyStringBuilder.AppendFormat("&client_secret={0}", clientSecret);
            }

            return requestBodyStringBuilder.ToString();
        }

        /// <summary>
        /// Gets the request body for redeeming a refresh token for an access token.
        /// </summary>
        /// <param name="refreshToken">The refresh token to redeem.</param>
        /// <returns>The request body for the redemption call.</returns>
        public string GetRefreshTokenRequestBody(string refreshToken, string appId, string returnUrl, string[] scopes, string clientSecret = null)
        {
            var requestBodyStringBuilder = new StringBuilder();
            requestBodyStringBuilder.AppendFormat("{0}={1}", OAuthConstants.RedirectUriKeyName, returnUrl);
            requestBodyStringBuilder.AppendFormat("&{0}={1}", OAuthConstants.ClientIdKeyName, appId);

            if (scopes != null)
            {
                requestBodyStringBuilder.AppendFormat("&{0}={1}", OAuthConstants.ScopeKeyName, WebUtility.UrlEncode(string.Join(" ", scopes)));
            }

            requestBodyStringBuilder.AppendFormat("&{0}={1}", OAuthConstants.RefreshTokenKeyName, refreshToken);
            requestBodyStringBuilder.AppendFormat("&{0}={1}", OAuthConstants.GrantTypeKeyName, OAuthConstants.RefreshTokenKeyName);

            if (!string.IsNullOrEmpty(clientSecret))
            {
                requestBodyStringBuilder.AppendFormat("&{0}={1}", OAuthConstants.ClientSecretKeyName, clientSecret);
            }

            return requestBodyStringBuilder.ToString();
        }
    }
}
