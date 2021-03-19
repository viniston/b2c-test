using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Identity.Client;
using System;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace RESTFunctions.Services
{
    public class Graph
    {
        public const string BaseUrl = "https://graph.microsoft.com/v1.0/";
        private static ILogger<Graph> _logger;
        public Graph(IOptions<ConfidentialClientApplicationOptions> opts, ILogger<Graph> logger)
        {
            _logger = logger;
            var thumb = opts.Value.ClientSecret;
            var cert = ReadCertificateFromStore(thumb);
            if (cert != null)
            {
                opts.Value.ClientSecret = string.Empty;
                _app = ConfidentialClientApplicationBuilder
                    .CreateWithApplicationOptions(opts.Value)
                    .WithCertificate(cert)
                    .Build();
            }
            else
                _app = ConfidentialClientApplicationBuilder
                    .CreateWithApplicationOptions(opts.Value)
                    //.WithClientSecret(thumb)
                    .Build();
        }
        IConfidentialClientApplication _app;

        public async Task<HttpClient> GetClientAsync()
        {
            var tokens = await _app.AcquireTokenForClient(
                new[] { "https://graph.microsoft.com/.default" })
                .ExecuteAsync();
            _logger.LogInformation($"Access Token is {tokens.AccessToken}");
            var http = new HttpClient();
            http.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
                "Bearer", tokens.AccessToken);
            return http;
        }

        /// <summary>
        /// Reads the certificate
        /// </summary>
        private static X509Certificate2 ReadCertificateFromStore(string thumbprint)
        {
            X509Certificate2 cert = null;
            try
            {
                _logger.LogInformation($"Starting ReadCertificateFromStore - thumbprint {thumbprint}");
                using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
                store.Open(OpenFlags.ReadOnly);
                var certCollection = store.Certificates;

                _logger.LogInformation("Find unexpired certificates");
                // Find unexpired certificates.
                var currentCerts = certCollection.Find(X509FindType.FindByTimeValid, DateTime.Now, false);

                _logger.LogInformation("From the collection of unexpired certificates, find the ones with the correct name");
                // From the collection of unexpired certificates, find the ones with the correct name.
                var signingCert = currentCerts.Find(X509FindType.FindByThumbprint, thumbprint, false);

                _logger.LogInformation("Return the first certificate in the collection, has the right name and is current");
                // Return the first certificate in the collection, has the right name and is current.
                cert = signingCert.OfType<X509Certificate2>().OrderByDescending(c => c.NotBefore).FirstOrDefault();
                _logger.LogInformation($"Found certificate {cert?.Thumbprint}");
                store.Close();
            }
            catch (Exception ex)
            {
                _logger.LogInformation($"ReadCertificateFromStore exception: {ex.Message}");
                Debug.WriteLine($"ReadCertificateFromStore exception: {0}", ex.Message);
            }
            return cert;
        }
    }
}
