import java.util.regex.*;

public class PhishingDetector {
    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("No URL provided.");
            return;
        }

        String url = args[0];

        if (isPhishing(url)) {
            System.out.println("Phishing");
        } else {
            System.out.println("Safe");
        }
    }

    public static boolean isPhishing(String url) {
        // Rule-based checks
        if (url.contains("@") || url.contains("login") || url.contains("verify") || url.contains("update")) {
            return true;
        }

        // IP-based URL pattern
        Pattern ipPattern = Pattern.compile("^(http|https)://(\\d{1,3}\\.){3}\\d{1,3}.*$");
        Matcher matcher = ipPattern.matcher(url);
        if (matcher.matches()) {
            return true;
        }

        // Very long URLs
        if (url.length() > 75) {
            return true;
        }

        return false;
    }
}
