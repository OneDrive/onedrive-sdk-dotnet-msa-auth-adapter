// ------------------------------------------------------------------------------
//  Copyright (c) 2015 Microsoft Corporation
// 
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
// 
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
// 
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.
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
                    Code = OAuthConstants.ErrorCodes.AuthenticationCancelled,
                    Message = "An error occurred during Azure Active Directory authentication.",
                },
                exception);
        }
    }
}
