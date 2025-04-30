using Microsoft.AspNetCore.Http;
using System.Text.Json;
using System.Collections.Generic;
using PhishGuardWeb.Models; // Import the Models namespace

namespace PhishGuardWeb.Extensions
{
    public static class SessionExtensions
    {
        private const string ActivityLogKey = "ActivityLog";

        public static void AddActivity(this ISession session, string taskPerformed, string input, string result) // Modified AddActivity
        {
            var log = session.GetActivityLog() ?? new List<PhishGuardWeb.Models.ActivityLog>();
            log.Add(new PhishGuardWeb.Models.ActivityLog
            {
                Timestamp = DateTime.Now,
                TaskPerformed = taskPerformed, // Use the provided parameters
                Input = input,
                Result = result
            });
            session.SetString(ActivityLogKey, JsonSerializer.Serialize(log));
        }

        public static List<PhishGuardWeb.Models.ActivityLog>? GetActivityLog(this ISession session)
        {
            var json = session.GetString(ActivityLogKey);
            return json == null ? null : JsonSerializer.Deserialize<List<PhishGuardWeb.Models.ActivityLog>>(json);
        }

        public static void ClearActivityLog(this ISession session)
        {
            session.Remove(ActivityLogKey);
        }
    }
}
