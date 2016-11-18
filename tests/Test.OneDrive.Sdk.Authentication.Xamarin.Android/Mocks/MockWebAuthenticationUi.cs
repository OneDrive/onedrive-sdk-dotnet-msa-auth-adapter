// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Test.OneDrive.Sdk.Authentication.Xamarin.Android.Mocks
{
    using Microsoft.OneDrive.Sdk.Authentication;
    using System;
    using System.Collections.Generic;
    using System.Threading.Tasks;

    public class MockWebAuthenticationUi : IWebAuthenticationUi
    {
        public Task<IDictionary<string, string>> AuthenticateAsync(Uri requestUri, Uri callbackUri)
        {
            IDictionary<string, string> result = new Dictionary<string, string>();
            return Task.FromResult(result);
        }
    }
}
