using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using PhishGuardWeb.Extensions;
using PhishGuardWeb.Services;
using PhishGuardWeb.Models;
using Microsoft.Extensions.Logging;

namespace PhishGuardWeb.Controllers
{
    public class HomeController : Controller
    {
        private readonly VirusTotalService _virusTotalService;
        private readonly IConfiguration _configuration;
        private readonly ILogger<HomeController> _logger;

        public HomeController(VirusTotalService virusTotalService, IConfiguration configuration, ILogger<HomeController> logger)
        {
            _virusTotalService = virusTotalService;
            _configuration = configuration;
            _logger = logger;
        }

        public IActionResult Landing() => View();
        public IActionResult Index() => View();

        [HttpGet]
        public IActionResult Scan() => View();

        [HttpPost]
        public async Task<IActionResult> Scan(string urlToCheck)
        {
            const string taskPerformed = "URL Scan";
            string input = urlToCheck;
            string result = "✅ Harmless";

            ActivityLog activityLog = new()
            {
                Timestamp = DateTime.Now,
                TaskPerformed = taskPerformed,
                Input = input,
                Result = result
            };

            HttpContext.Session.AddActivity(taskPerformed, input, result);
            _logger.LogInformation("URL Scan started for: {Url}", urlToCheck);

            bool isSuspicious = false;

            if (Regex.IsMatch(urlToCheck, @"(login|signin|update|security|verify|account).*(facebook|gmail|office365|instagram|bank|paypal)", RegexOptions.IgnoreCase))
            {
                isSuspicious = true;
                result = "⚠️ Potentially Suspicious (URL)";
                activityLog = new PhishGuardWeb.Models.ActivityLog
                {
                    Timestamp = DateTime.Now,
                    TaskPerformed = taskPerformed,
                    Input = input,
                    Result = result
                };
                HttpContext.Session.AddActivity(taskPerformed, input, result);
                _logger.LogWarning("Potentially suspicious keywords detected in URL: {Url}", urlToCheck);
            }
            if (Regex.IsMatch(urlToCheck, @"\.(php|asp|exe|scr)$", RegexOptions.IgnoreCase))
            {
                isSuspicious = true;
                if (result == "✅ Harmless")
                    result = "⚠️ Potentially Suspicious (URL)";
                activityLog = new PhishGuardWeb.Models.ActivityLog
                {
                    Timestamp = DateTime.Now,
                    TaskPerformed = taskPerformed,
                    Input = input,
                    Result = result
                };
                HttpContext.Session.AddActivity(taskPerformed, input, result);
                _logger.LogWarning("Potentially suspicious file extension detected in URL: {Url}", urlToCheck);
            }

            try
            {
                string virusTotalResult = await _virusTotalService.ScanURLAsync(urlToCheck);
                HttpContext.Session.AddActivity("VirusTotal API", urlToCheck, virusTotalResult); // Added taskPerformed and input
                _logger.LogInformation("VirusTotal API responded for URL: {Url} with result: {VirusTotalResult}", urlToCheck, virusTotalResult);

                if (virusTotalResult.Contains("Phishing Detected"))
                {
                    result = virusTotalResult;
                    activityLog = new PhishGuardWeb.Models.ActivityLog
                    {
                        Timestamp = DateTime.Now,
                        TaskPerformed = taskPerformed,
                        Input = input,
                        Result = result
                    };
                    HttpContext.Session.AddActivity(taskPerformed, input, result);
                    _logger.LogCritical("Phishing detected by VirusTotal for URL: {Url}", urlToCheck);
                }
                else if (isSuspicious && !virusTotalResult.Contains("No threats detected"))
                {
                    result = "⚠️ Suspicious (Local & VirusTotal)";
                    activityLog = new PhishGuardWeb.Models.ActivityLog
                    {
                        Timestamp = DateTime.Now,
                        TaskPerformed = taskPerformed,
                        Input = input,
                        Result = result
                    };
                    HttpContext.Session.AddActivity(taskPerformed, input, result);
                    _logger.LogWarning("URL: {Url} is suspicious (Local & VirusTotal)", urlToCheck);
                }
                else if (!isSuspicious && virusTotalResult.Contains("No threats detected"))
                {
                    result = "✅ Harmless";
                    activityLog = new PhishGuardWeb.Models.ActivityLog
                    {
                        Timestamp = DateTime.Now,
                        TaskPerformed = taskPerformed,
                        Input = input,
                        Result = result
                    };
                    HttpContext.Session.AddActivity(taskPerformed, input, result);
                    _logger.LogInformation("URL: {Url} is harmless", urlToCheck);
                }
                else if (isSuspicious && virusTotalResult.Contains("No threats detected"))
                {
                    result = "⚠️ Potentially Suspicious (URL)";
                    activityLog = new PhishGuardWeb.Models.ActivityLog
                    {
                        Timestamp = DateTime.Now,
                        TaskPerformed = taskPerformed,
                        Input = input,
                        Result = result
                    };
                    HttpContext.Session.AddActivity(taskPerformed, input, result);
                    _logger.LogWarning("URL: {Url} is potentially suspicious", urlToCheck);
                }
            }
            catch (Exception ex)
            {
                ViewBag.Error = $"Error scanning URL: {ex.Message}";
                result = "Error";
                activityLog = new PhishGuardWeb.Models.ActivityLog
                {
                    Timestamp = DateTime.Now,
                    TaskPerformed = taskPerformed,
                    Input = input,
                    Result = result
                };
                HttpContext.Session.AddActivity(taskPerformed, input, result);
                _logger.LogError(ex, "Error during VirusTotal API call for URL: {Url}", urlToCheck);
            }

            ViewBag.Verdict = result;
            return View();
        }

        public IActionResult History()
        {
            var activityLog = HttpContext.Session.GetActivityLog();
            return View(activityLog);
        }

        public IActionResult ClearHistory()
        {
            HttpContext.Session.ClearActivityLog();
            return RedirectToAction("History");
        }

        public IActionResult About() => View();

        public IActionResult Contact() => View();
    }
}
