// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.OneDrive.Sdk.Authentication
{
    using System;
    using System.Collections.Generic;

    internal class AndroidAuthenticationState
    {
        private static AndroidAuthenticationState instance = new AndroidAuthenticationState();
        private Dictionary<string, object> dictionary;

        protected AndroidAuthenticationState()
        {
            this.dictionary = new Dictionary<string, object>();
        }

        public static AndroidAuthenticationState Default
        {
            get { return instance; }
        }

        public string Add<T>(T state) where T : class
        {
            string key = Guid.NewGuid().ToString();
            this.dictionary.Add(key, state);
            return key;
        }

        public T Remove<T>(string key) where T : class
        {
            if (this.dictionary.ContainsKey(key))
            {
                T state = this.dictionary[key] as T;
                this.dictionary.Remove(key);
                return state;
            }

            return null;
        }
    }
}