using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Identity.Client;
using RESTFunctions.Models;
using RESTFunctions.Services;
using System;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace RESTFunctions
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            Trace.WriteLine("Starting Startup");
            services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_3_0);
            services.AddApplicationInsightsTelemetry("5164dd06-7613-4668-b19a-ee733264f9d1");


            //var cert = new X509Certificate2(@"C:\Playground\b2csamples\Scripts\MultiTenant\temp\RESTClientCert.pfx", "password");
            //var certificate = cert.GetRawCertData();
            //var b64 = Convert.ToBase64String(certificate);

            services.Configure<ClientCertificateOptions>(Configuration.GetSection("AuthCert"));
            services.Configure<ConfidentialClientApplicationOptions>(Configuration.GetSection("ClientCreds"));
            services.Configure<InvitationTokenOptions>(Configuration.GetSection("Invitation"));
            services.AddSingleton<Services.Graph>();
            services.AddTransient<Services.InvitationService>();
            services.AddTransient<Services.GraphOpenExtensions>();
            services.AddAuthentication(options =>
            {
                options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
            })
                .AddJwtBearer(jwtOptions =>
                {
                    jwtOptions.MetadataAddress = $"https://{Configuration["B2C:TenantName"]}.b2clogin.com/{Configuration["B2C:TenantId"]}/{Configuration["B2C:Policy"]}/v2.0/.well-known/openid-configuration";
                    Trace.WriteLine($"Oauth2 metadata: {jwtOptions.MetadataAddress}");
                    //jwtOptions.Authority = $"https://login.microsoftonline.com/tfp/{Configuration["B2C:TenantId"]}/{Configuration["B2C:Policy"]}/v2.0/";
                    jwtOptions.Audience = Configuration["B2C:ClientId"];
                    jwtOptions.Events = new JwtBearerEvents
                    {
                        OnAuthenticationFailed = (ctx) =>
                        {
                            Trace.WriteLine($"Bearer token validation failed: {ctx.Exception.Message}");
                            var addr = ctx.Options.MetadataAddress;
                            return Task.FromResult(0);
                        }
                    };
                });
        }
        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseRouting();
            //other middleware
            app.UseCertificateValidator();
            app.UseAuthentication();
            app.UseAuthorization();
            app.UseHttpsRedirection();
            //app.UseMvc();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
                endpoints.MapRazorPages();
                endpoints.MapControllerRoute(name: "default", pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
