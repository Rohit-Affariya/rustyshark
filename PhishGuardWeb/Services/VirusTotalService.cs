        using System.Net.Http.Headers;
        using System.Text.Json;
        using Microsoft.Extensions.Configuration; // Add this using statement

        namespace PhishGuardWeb.Services
        {
            public class VirusTotalService
            {
                private readonly string _apiKey;
                private readonly HttpClient _httpClient;

                public VirusTotalService(IConfiguration configuration) // Inject IConfiguration
                {
                    _apiKey = configuration.GetSection("VirusTotal")["ApiKey"]; // Correctly retrieve the key
                    _httpClient = new HttpClient();
                    _httpClient.DefaultRequestHeaders.Add("x-apikey", _apiKey);
                }

                public async Task<string> ScanURLAsync(string url)
                {
                    var postData = new Dictionary<string, string>
                    {
                        { "url", url }
                    };

                    var content = new FormUrlEncodedContent(postData);
                    var response = await _httpClient.PostAsync("https://www.virustotal.com/api/v3/urls", content);
                    var json = await response.Content.ReadAsStringAsync();

                    using var doc = JsonDocument.Parse(json);
                    if (doc.RootElement.TryGetProperty("data", out var dataElement) && dataElement.TryGetProperty("id", out var idElement))
                    {
                        string encodedId = idElement.GetString();

                        // Wait a bit for scan to process
                        await Task.Delay(3000);

                        var result = await _httpClient.GetAsync($"https://www.virustotal.com/api/v3/analyses/{encodedId}");
                        var resultJson = await result.Content.ReadAsStringAsync();

                        using var resultDoc = JsonDocument.Parse(resultJson);
                        if (resultDoc.RootElement.TryGetProperty("data", out var resultDataElement) && resultDataElement.TryGetProperty("attributes", out var attributesElement) && attributesElement.TryGetProperty("stats", out var statsElement))
                        {
                            int malicious = statsElement.GetProperty("malicious").GetInt32();
                            int suspicious = statsElement.GetProperty("suspicious").GetInt32();

                            if (malicious > 0 || suspicious > 0)
                                return $"Phishing Detected by VirusTotal ({malicious} malicious, {suspicious} suspicious)";
                            else
                                return "No threats detected by VirusTotal";
                        }
                        else
                        {
                             return "Error: Invalid response format from VirusTotal (missing data/attributes/stats)";
                        }
                    }
                    else
                    {
                       return "Error: Invalid response format from VirusTotal (missing data/id)";
                    }
                }
            }
        }
        