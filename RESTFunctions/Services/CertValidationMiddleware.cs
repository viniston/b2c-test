using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Diagnostics;
using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace RESTFunctions.Services
{
    public class CertValidationMiddleware
    {
        //private ILogger _logger;
        private readonly ILogger<CertValidationMiddleware> _logger;
        public CertValidationMiddleware(RequestDelegate next, IOptionsMonitor<ClientCertificateOptions> options, ILogger<CertValidationMiddleware> logger)
        {
            _logger = logger;
            _next = next;
            _optionsMonitor = options;
        }

        private readonly RequestDelegate _next;
        private readonly IOptionsMonitor<ClientCertificateOptions> _optionsMonitor;
        public async Task InvokeAsync(HttpContext context)
        {
            _logger.LogInformation("Hello World");
            _logger.LogInformation("Starting cert validation");
            Trace.WriteLine("Starting cert validation");
            var isAuthorized = false;
            ClaimsIdentity identity = null;
            _logger.LogInformation("Start Validating the client cert");
            _logger.LogInformation($"X-ARR-ClientCert={context.Request.Headers["X-ARR-ClientCert"]}");
            var certHeader = context.Request.Headers["X-ARR-ClientCert"];
            if (!string.IsNullOrEmpty(certHeader))
            {
                _logger.LogInformation("Certificate present");
                Trace.WriteLine("Certificate present");
                try
                {
                    var options = _optionsMonitor.CurrentValue;
                    Trace.WriteLine($"Issuer: {options.issuer}; subject: {options.subject}");
                    _logger.LogInformation($"Issuer: {options.issuer}; subject: {options.subject}");
                    var clientCertBytes = Convert.FromBase64String(certHeader);
                    var certificate = new X509Certificate2(clientCertBytes);
                    _logger.LogInformation("Date WILL be validated");
                    //if (!certificate.Verify()) throw new ApplicationException("Verify failed");
                    if (DateTime.Compare(DateTime.Now, certificate.NotBefore) < 0 ||
                        DateTime.Compare(DateTime.Now, certificate.NotAfter) > 0)
                    {
                        _logger.LogInformation("Validity period not correct");
                        throw new ApplicationException("Validity period");
                    }
                    Trace.WriteLine("Date validated");
                    _logger.LogInformation("Date validated");
                    isAuthorized =
                        (string.Compare(certificate.Thumbprint, options.thumbprint, true, CultureInfo.InvariantCulture) == 0)
                        && (string.Compare(certificate.Subject.Trim(), options.subject, true, CultureInfo.InvariantCulture) == 0)
                        && (string.Compare(certificate.Issuer.Trim(), options.issuer, true, CultureInfo.InvariantCulture) == 0);
                    if (isAuthorized)
                    {
                        _logger.LogInformation("X-ARR-ClientCert completely validated");
                        identity = new ClaimsIdentity(
                            new[] { new Claim("http://schemas.microsoft.com/ws/2008/06/identity/claims/role", "ief") });
                    }
                    else
                    {
                        _logger.LogInformation("X-ARR-ClientCert Failed validation");
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogInformation($"CertValidationMiddleware System exception: {ex.Message}");
                    Trace.WriteLine($"System exception: {ex.Message}");
                }
            }
            _logger.LogInformation($"Is authorized? {isAuthorized}");
            Trace.WriteLine($"Is authorized? {isAuthorized}");
            if (isAuthorized)
            {
                context.User = new ClaimsPrincipal(identity);
            }
            await _next(context);
        }
    }

    public static class MiddlewareExtensions
    {
        public static IApplicationBuilder UseCertificateValidator(this IApplicationBuilder app)
        {
            return app.UseMiddleware<CertValidationMiddleware>();
        }
    }

    public class ClientCertificateOptions
    {
        public string thumbprint { get; set; }
        public string issuer { get; set; }
        public string subject { get; set; }
    }
}
