// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.OneDrive.Sdk.Authentication
{
    using System;

    using Microsoft.Graph;
#if DESKTOP
    using Microsoft.IdentityModel.Clients.ActiveDirectory;
#endif

    internal static class BusinessAuthenticationExceptionHelper
    {
        internal static void HandleAuthenticationException(Exception exception)
        {
            bool isCancelled = false;

            if (exception != null)
            {
                var serviceException = exception as ServiceException;
                if (serviceException != null)
                {
                    throw serviceException;
                }

#if DESKTOP
                var adalException = exception as AdalException;
                if (adalException != null)
                {
                    isCancelled = string.Equals(adalException.ErrorCode, OAuthConstants.ErrorCodes.AuthenticationCancelled);
                }
#endif
            }

            if (isCancelled)
            {
                throw new ServiceException(
                    new Error
                    {
                       Code = OAuthConstants.ErrorCodes.AuthenticationCancelled,
                        Message = "User cancelled authentication.",
                    },
                    exception);
            }

            throw new ServiceException(
                new Error
                {
                    Code = OAuthConstants.ErrorCodes.AuthenticationFailure,
                    Message = "An error occurred during Azure Active Directory authentication.",
                },
                exception);
        }
    }
}
