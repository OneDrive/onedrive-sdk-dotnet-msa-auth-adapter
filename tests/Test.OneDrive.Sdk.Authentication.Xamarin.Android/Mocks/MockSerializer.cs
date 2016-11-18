// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Test.OneDrive.Sdk.Authentication.Xamarin.Android.Mocks
{
    using System.IO;

    using Microsoft.Graph;

    public delegate void DeserializeObjectStreamCallback(Stream stream);
    public delegate void DeserializeObjectStringCallback(string inputString);
    public delegate string SerializeObjectCallback(object serializableObject);

    public class MockSerializer : ISerializer
    {
        public object DeserializeObjectResponse { get; set; }

        public string SerializeObjectResponse { get; set; }

        public DeserializeObjectStreamCallback OnDeserializeObjectStream { get; set; }

        public DeserializeObjectStringCallback OnDeserializeObjectString { get; set; }

        public SerializeObjectCallback OnSerializeObject { get; set; }

        public T DeserializeObject<T>(string inputString)
        {
            if (this.OnDeserializeObjectString != null)
            {
                this.OnDeserializeObjectString(inputString);
            }

            return (T)this.DeserializeObjectResponse;
        }

        public T DeserializeObject<T>(Stream stream)
        {
            if (this.OnDeserializeObjectStream != null)
            {
                this.OnDeserializeObjectStream(stream);
            }

            return (T)this.DeserializeObjectResponse;
        }

        public string SerializeObject(object serializeableObject)
        {
            if (this.OnSerializeObject != null)
            {
                this.OnSerializeObject(serializeableObject);
            }

            return this.SerializeObjectResponse;
        }
    }
}
