// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.Identity.Client;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;

namespace CAE4Workloads
{
    /// <summary>
    /// Helper class to call a protected API and process its result
    /// </summary>
    public class ConfidentialProtectedApiCallHelper
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="httpClient">HttpClient used to call the protected API</param>
        public ConfidentialProtectedApiCallHelper(IConfidentialClientApplication msalconfidentialClientApplication, HttpClient httpClient)
        {
            HttpClient = httpClient;
            MSALConfidentialClientApplication = msalconfidentialClientApplication;
        }

        protected HttpClient HttpClient { get; private set; }
        protected IConfidentialClientApplication MSALConfidentialClientApplication { get; private set; }


        /// <summary>
        /// Calls the protected web API and processes the result
        /// </summary>
        /// <param name="webApiUrl">URL of the web API to call (supposed to return Json)</param>
        /// <param name="scopes">Scopes required to call the API</param>
        /// <param name="processResult">Callback used to process the result of the call to the web API</param>
        public async Task<bool> CallWebApiAndProcessResultASync(string webApiUrl, string[] scopes, Action<JObject> processResult)
        {
            string ClaimChallenge = null;
            bool retryForCAE = true;
            bool returnContinueFlag = true;

            do 
            {
                Console.WriteLine($"Before GetToken {DateTime.Now}");
                AuthenticationResult authResult = await GetAccessToken(MSALConfidentialClientApplication, scopes, ClaimChallenge);
                Console.WriteLine($"After GetToken {DateTime.Now}");
                if (authResult != null)
                {
                    var defaultRequestHeaders = HttpClient.DefaultRequestHeaders;
                    if (defaultRequestHeaders.Accept == null || !defaultRequestHeaders.Accept.Any(m => m.MediaType == "application/json"))
                    {
                        HttpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                    }
                    defaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", authResult.AccessToken);

                    Console.WriteLine($"Before API {DateTime.Now}");
                    HttpResponseMessage response = await HttpClient.GetAsync(webApiUrl);
                    Console.WriteLine($"After API {DateTime.Now}");
                    if (response.IsSuccessStatusCode)
                    {
                        string json = await response.Content.ReadAsStringAsync();
                        JObject APIResult = JsonConvert.DeserializeObject(json) as JObject;
                        processResult(APIResult);
                        retryForCAE = false;
                    }
                    else
                    {
                        Console.WriteLine($"Process challenge {DateTime.Now}");
                        if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized && response.Headers.WwwAuthenticate.Any())
                        {
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine("Call to the web API is unauthorized.");

                            AuthenticationHeaderValue bearer = response.Headers.WwwAuthenticate.First(v => v.Scheme == "Bearer");
                            IEnumerable<string> parameters = bearer.Parameter.Split(',').Select(v => v.Trim()).ToList();
                            var error = GetParameter(parameters, "error");
                            if (error != null && error == "insufficient_claims")
                            {
                                var claimChallengeParameter = GetParameter(parameters, "claims");
                                if (claimChallengeParameter != null && ClaimChallenge == null)
                                {
                                    var claimChallengebase64Bytes = System.Convert.FromBase64String(claimChallengeParameter);
                                    ClaimChallenge = System.Text.Encoding.UTF8.GetString(claimChallengebase64Bytes);
                                    Console.WriteLine($"Continuous Access Evaluation claim challenge {ClaimChallenge}.");
                                }
                                else
                                {
                                    // Only retry for claims challenge once
                                    retryForCAE = false;
                                    returnContinueFlag = false;
                                }
                            }
                        }
                        else
                        {
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine($"Failed to call the web API: {response.StatusCode}");
                            retryForCAE = false;
                        }
                        Console.WriteLine($"Done Process challenge {DateTime.Now}");
                    }
                }
                else
                {
                    retryForCAE = false;
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Failed to call the web API, no access token received");
                }
            } while (retryForCAE);

            Console.ResetColor();
            return returnContinueFlag;
        }

        private async static Task<AuthenticationResult> GetAccessToken(IConfidentialClientApplication MSALConfidentialClientApplication, string[] scopes, string claimsChallenge = null)
        {
            AuthenticationResult authResult = null;
            try
            {
                // Acquire the token for MS Graph
                authResult = await MSALConfidentialClientApplication.AcquireTokenForClient(scopes).WithClaims(claimsChallenge).ExecuteAsync();

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("Token acquired from MSAL");
                Console.WriteLine($"Token expires at: {authResult.ExpiresOn.ToLocalTime()}");
                Console.WriteLine($"Token Source: {authResult.AuthenticationResultMetadata.TokenSource}");
                Console.ResetColor();
            }
            catch (MsalServiceException ex)
            {
                if (ex.Message.Contains("AADSTS70011"))
                {
                    // Invalid scope. The scope has to be of the form "https://resourceurl/.default"
                    // Mitigation: change the scope to be as expected
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Scope provided is not supported");
                    Console.ResetColor();
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"{ex.Message}");
                    Console.WriteLine($"{ex.ErrorCode}");
                    Console.WriteLine($"{ex.Claims}");
                    Console.ResetColor();
                }
            }
            catch (Exception finalEx)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(finalEx.Message);
                Console.ResetColor();
            }

            return authResult;
        }
        private static string GetParameter(IEnumerable<string> parameters, string parameterName)
        {
            int offset = parameterName.Length + 1;
            return parameters.FirstOrDefault(p => p.StartsWith($"{parameterName}="))?.Substring(offset)?.Trim('"');
        }
    }
}
