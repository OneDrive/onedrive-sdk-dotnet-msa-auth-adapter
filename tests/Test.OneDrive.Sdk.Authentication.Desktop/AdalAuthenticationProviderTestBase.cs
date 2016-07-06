// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Test.OneDrive.Sdk.Authentication.Desktop
{
    using System.Net.Http;

    using Microsoft.Graph;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using Mocks;

    public class AuthenticationTestBase
    {
        protected const string ClientId = "12345";
        protected const string ReturnUrl = "https://login.live.com/return";
        protected const string ServiceEndpointUrl = "https://localhost";
        protected const string ServiceResourceId = "https://localhost/resource/";

        protected MockAdalCredentialCache credentialCache;
        protected MockHttpProvider httpProvider;
        protected HttpResponseMessage httpResponseMessage;
        protected ISerializer serializer;

        [TestInitialize]
        public virtual void Setup()
        {
            this.credentialCache = new MockAdalCredentialCache();
            this.httpResponseMessage = new HttpResponseMessage();
            this.serializer = new Serializer();
            this.httpProvider = new MockHttpProvider(this.httpResponseMessage, this.serializer);
        }

        [TestCleanup]
        public virtual void Cleanup()
        {
            this.httpResponseMessage.Dispose();
        }
    }
}
