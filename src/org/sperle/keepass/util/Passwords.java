package org.sperle.keepass.util;

import java.io.UnsupportedEncodingException;

// TODO test this class
public final class Passwords {
    public static final String UTF8_ENCODING = "UTF-8";
    public static final byte[] EMPTY_PASSWORD = Passwords.fromString("");
    
    /**
     * Converts a password string into a byte array.
     */
    public static byte[] fromString(String s) {
        if(s == null) return null;
        
        try {
            return s.getBytes(UTF8_ENCODING);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException("UTF-8 encoding not supported on this system");
        }
    }
    
    /**
     * Converts a byte array into a password string.
     */
    public static String toString(byte data[]) {
        if(data == null) return null;
        try {
            return new String(data, UTF8_ENCODING).trim();
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException("UTF-8 encoding not supported on this system");
        }
    }
    
    /**
     * Checks, if given password is an empty password.
     */
    public static boolean isEmpty(byte data[]) {
        return ByteArrays.equals(EMPTY_PASSWORD, data);
    }
    
    /**
     * Returns the correct encoded master password representation as byte array.
     */
    public static byte[] getEncodedMasterPassword(String masterPassword) {
        if(masterPassword == null) return null;
        byte[] encMasterPassword = null;
        try {
            encMasterPassword = masterPassword.getBytes(getCorrectMasterPasswordEncoding());
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace(); // Can only happen during development
        }
        return encMasterPassword;
    }

    /**
     * Attention: password encoding is ISO-8859-(1-9) -> depending on the system.
     * Dev problem (eg. when running the tests): Linux returns "UTF-8" as standard encoding!
     */
    private static String getCorrectMasterPasswordEncoding() {
        String encoding = System.getProperty("microedition.encoding"); // get system encoding
        if(encoding == null || !encoding.startsWith("ISO-8859")) {
            encoding = "ISO-8859-1";
        }
        return encoding;
    }
}
