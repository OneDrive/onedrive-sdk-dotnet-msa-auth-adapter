using Microsoft.OneDrive.Sdk.Authentication;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Generic;
using System.Linq;
using static Microsoft.OneDrive.Sdk.Authentication.CredentialVault;
using System.IO;
using Moq;

namespace Test.OneDrive.Sdk.Authentication.Desktop
{
    [TestClass]
    public class CredentialVaultTests
    {
        InMemoryFileSystem fileSystem = new InMemoryFileSystem();
        CredentialVault credentialVault;
        CredentialCache credentialCache;
        AccountSession accountSession;
        CredentialCache retrievedCache;

        [TestInitialize]
        public void TestInitialize()
        {
            var dict = new Dictionary<string, string>()
            {
                { OAuthConstants.AccessTokenKeyName, "token"},
                { OAuthConstants.UserIdKeyName, "myUserId" }
            };
            accountSession = new AccountSession(dict, "myClientId");
            credentialCache = new CredentialCache();
            credentialCache.AddToCache(accountSession);
            credentialVault = new CredentialVault("myClientId", fileSystem: fileSystem);
            credentialVault.AddCredentialCacheToVault(credentialCache);
            retrievedCache = new CredentialCache();
        }

        [TestMethod]
        public void CredentialVaultTests_AddRetrieveSucceeds()
        {
            Assert.AreEqual(1, fileSystem.fs.Count, "File system should be storing only one cache");
            bool success = credentialVault.RetrieveCredentialCache(retrievedCache);
            Assert.IsTrue(success, "CredentialCache not found in vault.");
            AccountSession retrievedAccountSession = retrievedCache.GetResultFromCache("myClientId", "myUserId");
            Assert.IsNotNull(retrievedAccountSession, "AccountSession is null.");
            Assert.AreEqual("token", retrievedAccountSession.AccessToken, "AccountSession not stored properly.");
        }

        [TestMethod]
        public void CredentialVaultTests_DeleteSucceeds()
        {
            bool success1 = credentialVault.DeleteStoredCredentialCache();
            Assert.IsTrue(success1, "CredentialCache not found in vault.");
            bool success2 = credentialVault.RetrieveCredentialCache(retrievedCache);
            Assert.IsFalse(success2, "CredentialCache is not erased from vault.");
            AccountSession retrievedAccountSession = retrievedCache.GetResultFromCache("myClientId", "myUserId");
            Assert.IsNull(retrievedAccountSession, "AccountSession must be null.");
        }

        [TestMethod]
        public void CredentialVaultTests_ProtectMethodCalled()
        {
            var mockProtectedData = new Mock<IProtectedData>();
            credentialVault = new CredentialVault("myClientId", null, fileSystem, mockProtectedData.Object);
            credentialVault.AddCredentialCacheToVault(credentialCache);
            mockProtectedData.Verify(
                mock => mock.Protect(
                    It.Is<byte[]>(b => b.SequenceEqual(credentialCache.GetCacheBlob()))),
                Times.Once(),
                "Protect method not called with CredentialCache as parameter.");
        }

        [TestMethod]
        public void CredentialVaultTests_ProtectMethodTransformsData()
        {
            ProtectedDataDefault protectedData = new ProtectedDataDefault();
            byte[] b = { 1, 2, 3 };
            var c = protectedData.Protect(b);
            Assert.IsFalse(b.SequenceEqual(c),"Protect method does not transform data.");
        }
    }

    internal class InMemoryFileSystem : IFile
    {
        public Dictionary<string, byte[]> fs = new Dictionary<string, byte[]>();

        public void Delete(string path)
        {
            fs.Remove(path);
        }

        public bool Exists(string path)
        {
            return fs.ContainsKey(path);
        }

        public Stream OpenWrite(string path)
        {
            fs.Add(path, new byte[550]);
            return new MemoryStream(fs[path]);
        }

        public byte[] ReadAllBytes(string path)
        {
            return fs[path];
        }
    }
}