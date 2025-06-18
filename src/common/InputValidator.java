package common;

public class InputValidator {
    private static final String ALLOWED_CHARS = "[a-zA-Z0-9 éèàçùêëïöüâäôûÉÈÀÇÙÊËÏÖÜÂÄÔÛ_-]+";

    public static boolean isValidInput(String input) {
        if (input == null || input.trim().isEmpty()) {
            return false;
        }
        return input.matches(ALLOWED_CHARS);
    }

    public static boolean isValidServiceName(String service) {
        return isValidInput(service) && service.length() <= 50;
    }

    public static boolean isValidUsername(String username) {
        return isValidInput(username) && username.length() <= 30;
    }

    public static boolean isValidPassword(String password) {
        return password != null && password.length() >= 4 && password.length() <= 100;
    }

    public static String sanitize(String input) {
        if (input == null) return "";
        return input.replace(";", "").replace("\n", "").replace("\r", "");
    }
}