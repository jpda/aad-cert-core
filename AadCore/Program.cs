using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace AadCore
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var d = new DoThings();
            Console.WriteLine(d.Go().Result);
            Console.WriteLine("all finished");
            Console.ReadLine();
        }
    }

    public class DoThings
    {
        private const string Certpath = @"<pfx>";
        private const string ClientId = "<cid>";
        private const string Authority = "https://login.windows.net/<tenant>";
        private const string Resource = "https://graph.microsoft.com"; // your resource id
        private const string Url = "https://graph.microsoft.com/v1.0/users"; //authenticated url

        public async Task<AuthenticationResult> Go()
        {

            var certf = System.IO.File.ReadAllBytes(Certpath);
            var id = ClientId;
            var cert = new X509Certificate2(certf, "<pfx password>");
            Console.WriteLine($"Reading cert {cert.SubjectName.Name} ({cert.Thumbprint})...");

            Console.WriteLine($"Creating aad proxy for {Authority}...");
            var ac = new AuthenticationContext(Authority);
            //var ca = new
            Console.WriteLine("Creating new signed assertion...");
            var cred = new ClientAssertionCert(id, cert);
            Console.WriteLine($"Getting token for {Resource}...");
            AuthenticationResult token = null;
            try
            {
                token = await ac.AcquireTokenAsync(Resource, cred);
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("oh snap");
                Console.WriteLine(ex);
                return token;
            }

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("word up");
            foreach (var p in typeof(AuthenticationResult).GetProperties())
            {
                if (p.GetValue(token) == null) continue;
                var pval = p.GetValue(token).ToString();
                Console.WriteLine($"{p.Name}: {(pval.Length > 100 ? pval.Substring(0, 100) : pval)}");
            }

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("Making authenticated request...");
            try
            {
                var response = await MakeAuthenticatedRequest(Url, token.AccessToken);
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine("--- response ---");
                Console.WriteLine(response);
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("oh snap");
                Console.WriteLine(ex);
            }

            return token;
        }

        public async Task<string> MakeAuthenticatedRequest(string url, string token)
        {
            var w = new HttpClient();
            w.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            var response = await w.GetStringAsync(url);
            return response;
        }
    }
}