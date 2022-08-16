// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.Identity.Client;
using Microsoft.Identity.Web;
using Newtonsoft.Json.Linq;
using System;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates; //Only import this if you are using certificate
// using System.Threading;
using System.Threading.Tasks;
using TimersTimer = System.Timers.Timer;

namespace CAE4Workloads
{
    /// <summary>
    /// This sample shows how to query the Microsoft Graph from a daemon application
    /// which uses application permissions.
    /// For more information see https://aka.ms/msal-net-client-credentials
    /// </summary>
    class Program
    {
        // Even if this is a console application here, a daemon application is a confidential client application
        private static IConfidentialClientApplication _MSALConfidentialClientApplication;
        private static AuthenticationConfig _config;
        private static HttpClient _httpClient;
        private static ConfidentialProtectedApiCallHelper _apiCaller;
        private static Double _timeout = 30000.0;
        private static TimersTimer _timer = new TimersTimer(_timeout);

        // With client credentials flows the scopes is ALWAYS of the shape "resource/.default", as the 
        // application permissions need to be set statically (in the portal or by PowerShell), and then granted by
        // a tenant administrator. 
        private static string[] _scopes;

        static void Main(string[] args)
        {
            Console.ResetColor();
            _config = AuthenticationConfig.ReadFromJsonFile("appsettings.json");

            PrepareConfidentialClient();

            _scopes = new string[] { $"{_config.ApiUrl}.default" };
            _httpClient = new HttpClient();
            _apiCaller = new ConfidentialProtectedApiCallHelper(_MSALConfidentialClientApplication, _httpClient);

            Console.WriteLine($"The Graph Api will be called every {_timeout / 1000} seconds unless any key was pressed.");

            _timer.Elapsed += CallGraphApi;

            _timer.AutoReset = true;
            _timer.Enabled = true;

            Console.WriteLine("Press any key to exit");
            Console.ReadKey();
        }

        private static bool wait = false;

        private static void CallGraphApi(Object source, System.Timers.ElapsedEventArgs e)
        {
            if (wait)
            {
                Console.WriteLine("Waiting");
                return;
            }
            try
            {
                RunAsync().GetAwaiter().GetResult();
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(ex.Message);
                Console.ResetColor();
            }
        }

        private static async Task RunAsync()
        {
            wait = true;
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"At {DateTime.Now.ToString("o")} calling MS Graph");
            Console.ResetColor();
            var contiune = await _apiCaller.CallWebApiAndProcessResultASync($"{_config.ApiUrl}v1.0/users/kyle@idfordevs.onmicrosoft.com?&$orderBy=displayName&$select=id,displayName,mail", _scopes, Display);
            wait = false;

            if (contiune == false)
            {
                Console.WriteLine("Process finished due to Continuous Access Evaluation.");
                Console.WriteLine("Press any key to exit");
                _timer.Stop();
            }
        }

        /// <summary>
        /// Prepares the MSAL's confidential client.
        /// </summary>
        /// <returns></returns>
        private static void PrepareConfidentialClient()
        {            

            // You can run this sample using ClientSecret or Certificate. The code will differ only when instantiating the IConfidentialClientApplication
            bool isUsingClientSecret = AppUsesClientSecret(_config);

            if (isUsingClientSecret)
            {
                _MSALConfidentialClientApplication = ConfidentialClientApplicationBuilder.Create(_config.ClientId)
                    .WithClientSecret(_config.ClientSecret)
                    .WithAuthority(new Uri(_config.Authority))
                    .WithLogging(Log, LogLevel.Error, true)
                    .WithClientCapabilities(new[] { "cp1" }) // Declare this app to be able to receive CAE events
                    .Build();
            }

            else
            {
                X509Certificate2 certificate = ReadCertificate(_config.CertificateName);
                _MSALConfidentialClientApplication = ConfidentialClientApplicationBuilder.Create(_config.ClientId)
                    .WithCertificate(certificate)
                    .WithAuthority(new Uri(_config.Authority))
                    .WithLogging(Log, LogLevel.Error, false)
                    .WithClientCapabilities(new[] { "cp1" }) // Declare this app to be able to receive CAE events
                    .Build();
            }
        }

        ///
        /// Log
        /// 
        private static  void Log(LogLevel level, string message, bool containsPii)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"{level} {message}");
            Console.ResetColor();
        }


        /// <summary>
        /// Display the result of the Web API call
        /// </summary>
        /// <param name="result">Object to display</param>
        private static void Display(JObject result)
        {
            Console.ForegroundColor = ConsoleColor.Gray;
            foreach (JProperty child in result.Properties().Where(p => !p.Name.StartsWith("@")))
            {
                Console.WriteLine($"{child.Name} = {child.Value}");
            }
        }

        /// <summary>
        /// Checks if the sample is configured for using ClientSecret or Certificate. This method is just for the sake of this sample.
        /// You won't need this verification in your production application since you will be authenticating in AAD using one mechanism only.
        /// </summary>
        /// <param name="config">Configuration from appsettings.json</param>
        /// <returns></returns>
        private static bool AppUsesClientSecret(AuthenticationConfig config)
        {
            string clientSecretPlaceholderValue = "[Enter here a client secret for your application]";
            string certificatePlaceholderValue = "[Or instead of client secret: Enter here the name of a certificate (from the user cert store) as registered with your application]";

            if (!String.IsNullOrWhiteSpace(config.ClientSecret) && config.ClientSecret != clientSecretPlaceholderValue)
            {
                return true;
            }

            else if (!String.IsNullOrWhiteSpace(config.CertificateName) && config.CertificateName != certificatePlaceholderValue)
            {
                return false;
            }

            else
                throw new Exception("You must choose between using client secret or certificate. Please update appsettings.json file.");
        }

        private static X509Certificate2 ReadCertificate(string certificateName)
        {
            if (string.IsNullOrWhiteSpace(certificateName))
            {
                throw new ArgumentException("certificateName should not be empty. Please set the CertificateName setting in the appsettings.json", "certificateName");
            }
            CertificateDescription certificateDescription = CertificateDescription.FromStoreWithDistinguishedName(certificateName);
            DefaultCertificateLoader defaultCertificateLoader = new DefaultCertificateLoader();
            defaultCertificateLoader.LoadIfNeeded(certificateDescription);
            return certificateDescription.Certificate;
        }
    }
}
