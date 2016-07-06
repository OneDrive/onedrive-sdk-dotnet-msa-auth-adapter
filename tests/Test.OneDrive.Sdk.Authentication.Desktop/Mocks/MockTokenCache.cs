// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Test.OneDrive.Sdk.Authentication.Desktop.Mocks
{
    using Microsoft.OneDrive.Sdk.Authentication;
    using Moq;

    public class MockTokenCache : Mock<ITokenCache>
    {
        public MockTokenCache()
            : base(MockBehavior.Strict)
        {
            this.SetupAllProperties();

            this.Setup(cache => cache.Clear());
            this.Setup(cache => cache.Deserialize(It.IsAny<byte[]>()));
            this.Setup(cache => cache.Serialize()).Returns(new byte[0]);
        }
    }
}
