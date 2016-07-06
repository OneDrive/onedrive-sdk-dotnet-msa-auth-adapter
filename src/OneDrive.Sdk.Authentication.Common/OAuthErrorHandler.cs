// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.OneDrive.Sdk.Authentication
{
    using System.Collections.Generic;

    using Microsoft.Graph;

    public static class OAuthErrorHandler
    {
        public static void ThrowIfError(IDictionary<string, string> responseValues)
        {
            if (responseValues != null)
            {
                string error = null;
                string errorDescription = null;

                if (responseValues.TryGetValue(OAuthConstants.ErrorDescriptionKeyName, out errorDescription) ||
                    responseValues.TryGetValue(OAuthConstants.ErrorKeyName, out error))
                {
                    OAuthErrorHandler.ParseAuthenticationError(error, errorDescription);
                }
            }
        }

        private static void ParseAuthenticationError(string error, string errorDescription)
        {
            throw new ServiceException(
                new Error
                {
                    Code = OAuthConstants.ErrorCodes.AuthenticationFailure.ToString(),
                    Message = errorDescription ?? error
                });
        }
    }
}
