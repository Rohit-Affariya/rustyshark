using System.ComponentModel.DataAnnotations;

namespace PhishGuardWeb.Models
{
    public class ScanResult
    {
        [Required(AllowEmptyStrings = false)]
        public string URL { get; set; } = string.Empty;
        [Required(AllowEmptyStrings = false)]
        public string Result { get; set; } = string.Empty;
        public DateTime ScanDate { get; set; }
    }
}
