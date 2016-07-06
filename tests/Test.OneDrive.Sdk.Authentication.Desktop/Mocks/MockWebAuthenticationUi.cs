// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Test.OneDrive.Sdk.Authentication.Desktop.Mocks
{
    using System;
    using System.Collections.Generic;
    using System.Threading.Tasks;

    using Microsoft.OneDrive.Sdk.Authentication;
    using Moq;

    public class MockWebAuthenticationUi : Mock<IWebAuthenticationUi>
    {
        private IDictionary<string, string> responseValues;

        public MockWebAuthenticationUi()
            : this(new Dictionary<string, string>())
        {
        }

        public MockWebAuthenticationUi(IDictionary<string, string> responseValues)
            : base(MockBehavior.Strict)
        {
            this.responseValues = responseValues;

            this.Setup(
                webUi => webUi.AuthenticateAsync(It.IsAny<Uri>(), It.IsAny<Uri>()))
                    .Returns(Task.FromResult(this.responseValues));
        }
    }
}
