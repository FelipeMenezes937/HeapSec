package antivirus.scanner;

public class ExtensionChecker {

    private static final String[] DOUBLE_EXTENSIONS = {
        ".pdf.exe", ".doc.exe", ".xls.exe", ".ppt.exe",
        ".jpg.exe", ".png.exe", ".gif.exe",
        ".html.exe", ".zip.exe", ".rar.exe",
        ".js.exe", ".vbs.exe", ".bat.exe"
    };

    public boolean check(String fileName) {
        String lower = fileName.toLowerCase();
        for (String ext : DOUBLE_EXTENSIONS) {
            if (lower.endsWith(ext)) {
                return true;
            }
        }
        return false;
    }
}