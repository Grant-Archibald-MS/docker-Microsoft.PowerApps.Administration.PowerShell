using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Identity.Client;

namespace Microsoft.PowerPlatform.CenterOfExcellence.Authentication
{
    public class ActiveDirectoryAuth
    {
        public static AuthenticationResult GetDeviceCodeAccessToken(string applicationId, string authBaseUri, string[] scopes) {
            var pca = Microsoft.Identity.Client.PublicClientApplicationBuilder.Create(applicationId).WithAuthority($"{authBaseUri}/common").WithDefaultRedirectUri();            
            var built = pca.Build();
            
            return built.AcquireTokenWithDeviceCode( scopes.AsEnumerable(), (deviceCodeResult) => {
                Console.WriteLine(deviceCodeResult.Message);
                return Task.FromResult(0);
            }).ExecuteAsync().Result;
        }
    }
}
