package com.bearmod.utils;

/**
 * Utility class for string operations
 */
public class StringUtils {
    
    /**
     * Checks if a string is null or empty
     * 
     * @param str The string to check
     * @return true if the string is null or empty, false otherwise
     */
    public static boolean isEmpty(String str) {
        return str == null || str.trim().length() == 0;
    }
    
    /**
     * Reverses a string
     * 
     * @param str The string to reverse
     * @return The reversed string, or empty string if input is null
     */
    public static String reverse(String str) {
        if (str == null) {
            return "";
        }
        return new StringBuilder(str).reverse().toString();
    }
    
    /**
     * Counts the occurrences of a character in a string
     * 
     * @param str The string to search in
     * @param c The character to count
     * @return The number of occurrences, or 0 if the string is null
     */
    public static int countChar(String str, char c) {
        if (str == null) {
            return 0;
        }
        
        int count = 0;
        for (int i = 0; i < str.length(); i++) {
            if (str.charAt(i) == c) {
                count++;
            }
        }
        return count;
    }
}
