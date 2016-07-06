// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Test.OneDrive.Sdk.Authentication.Desktop
{
    using System.Collections.Generic;

    using Microsoft.Graph;
    using Microsoft.OneDrive.Sdk.Authentication;
    using Microsoft.VisualStudio.TestTools.UnitTesting;

    [TestClass]
    public class OAuthErrorHandlerTests
    {
        [TestMethod]
        [ExpectedException(typeof(ServiceException))]
        public void ValidateError_NoDescription()
        {
            var errorMessage = "This is an error.";
            var responseValues = new Dictionary<string, string>
            {
                { OAuthConstants.ErrorKeyName, errorMessage },
            };

            try
            {
                OAuthErrorHandler.ThrowIfError(responseValues);
            }
            catch(ServiceException exception)
            {
                Assert.AreEqual(OAuthConstants.ErrorCodes.AuthenticationFailure, exception.Error.Code, "Unexpected error code.");
                Assert.AreEqual(errorMessage, exception.Error.Message, "Unexpected error message.");

                // Re-throw to kick off final validation.
                throw;
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ServiceException))]
        public void ValidateError_WithDescription()
        {
            var errorMessage = "This is an error.";
            var errorDescription = "Error description";
            var responseValues = new Dictionary<string, string>
            {
                { OAuthConstants.ErrorDescriptionKeyName, errorDescription },
                { OAuthConstants.ErrorKeyName, errorMessage },
            };

            try
            {
                OAuthErrorHandler.ThrowIfError(responseValues);
            }
            catch (ServiceException exception)
            {
                Assert.AreEqual(OAuthConstants.ErrorCodes.AuthenticationFailure, exception.Error.Code, "Unexpected error code.");
                Assert.AreEqual(errorDescription, exception.Error.Message, "Unexpected error message.");

                // Re-throw to kick off final validation.
                throw;
            }
        }
    }
}
