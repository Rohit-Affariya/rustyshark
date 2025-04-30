using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace PhishGuardWeb.Services
{
    public class JavaScannerService
    {
        public async Task<string> ScanFileAsync(string filePath)
        {
            // রক্ষার null path
            if (string.IsNullOrEmpty(filePath))
            {
                return "Error: File path is null or empty.";
            }
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "java",
                    Arguments = $"-jar scanner.jar {filePath}",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                    StandardOutputEncoding = Encoding.UTF8,
                    StandardErrorEncoding = Encoding.UTF8,
                }
            };

            process.Start();
            string output = await process.StandardOutput.ReadToEndAsync();
            string error = await process.StandardError.ReadToEndAsync();
            await process.WaitForExitAsync();

            if (process.ExitCode != 0)
            {
                return $"Error: Java scanner exited with code {process.ExitCode}.  Error output: {error}";
            }

            if (string.IsNullOrEmpty(output))
            {
                return "Error: Java scanner returned empty output.";
            }

            return output.Trim();
        }
    }
}