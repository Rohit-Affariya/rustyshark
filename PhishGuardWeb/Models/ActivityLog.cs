        using System;

        namespace PhishGuardWeb.Models
        {
            public class ActivityLog
            {
                public DateTime Timestamp { get; set; }
                public string? TaskPerformed { get; set; } // e.g., "URL Scan", "File Scan"
                public string? Input { get; set; }       // The URL or file name
                public string? Result { get; set; }        // The result of the scan (e.g., "Phishing", "Safe", "Error")
            }
        }
        