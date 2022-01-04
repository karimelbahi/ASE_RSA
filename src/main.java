import java.util.*;
import java.io.*;

class Main {

    public static String StringChallenge(String str) {

        int replacePosition = 0;
        StringBuilder strBuilder = new StringBuilder("empty empty empty empty empty");
        float floatRate = Float.parseFloat(str);
        for (int i = 0; i < (int) floatRate--; ) {
            strBuilder.replace(replacePosition, replacePosition + 5, "full");
            replacePosition += 5;
        }
        if (floatRate % 1 != 0) {
            strBuilder.replace(replacePosition, replacePosition + 5, "half");
        }

        return strBuilder.toString();
    }

    // Function to remove spaces and convert
    // into camel case
    static String convert(String s) {

        // to count spaces
        int cnt = 0;
        int n = s.length();
        char ch[] = s.toCharArray();
        int res_ind = 0;

        for (int i = 0; i < n; i++) {

            // check for spaces in the sentence
            if (ch[i] == ' ') {
                cnt++;
                // conversion into upper case
                ch[i + 1] = Character.toUpperCase(ch[i + 1]);
                continue;
            }

            // If not space, copy character
            else
                ch[res_ind++] = ch[i];
        }

        // new string will be resuced by the
        // size of spaces in the original string
        return String.valueOf(ch, 0, n - cnt);
    }


    static String CamelCase(String str) {
        StringBuilder strBuilder = new StringBuilder(str.replaceAll("[^A-Za-z0-9]", " "));

        for (int x = 0; x < str.length(); x++) {
            if (x == 0) {
                strBuilder.replace(x, x + 1, String.valueOf(Character.toLowerCase(strBuilder.charAt(x))));
                continue;
            }

            if (Character.isLetter(strBuilder.charAt(x)) && !Character.isLetter(strBuilder.charAt(x-1))) {
                strBuilder.replace(x, x + 1, String.valueOf(Character.toUpperCase(strBuilder.charAt(x))));
            } else {
                strBuilder.replace(x, x + 1, String.valueOf(Character.toLowerCase(strBuilder.charAt(x))));
            }
        }

        return strBuilder.toString().replaceAll("\\s", "");
    }

    public static void main(String[] args) {

        String str = "cAts AND*Dogs-are Awesome";
        System.out.println(CamelCase(str).trim());
    }

}