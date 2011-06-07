/*
    Copyright (c) 2009-2010 Christoph Sperle <keepassmobile@gmail.com>
    
    This file is part of KeePassMobile.

    KeePassMobile is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    KeePassMobile is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with KeePassMobile.  If not, see <http://www.gnu.org/licenses/>.

*/

package org.sperle.keepass.util;

import java.io.UnsupportedEncodingException;

import com.sun.cldc.i18n.Helper;

/**
 * Helper class with macro methods for the work with binary data.
 */
public class BinaryData {
    public static final byte STRING_TERMINATOR = 0;
    public static final int  PACKEDDATE_LENGTH = 5;
    public static final String UTF8_ENCODING   = "UTF-8";
    
    /**
     * Converts binary data back into an integer.
     */
    public static int toInt(byte data[], int offset) {
	return (data[offset + 0] & 0xFF) + 
	      ((data[offset + 1] & 0xFF) << 8) + 
	      ((data[offset + 2] & 0xFF) << 16) +
	      ((data[offset + 3] & 0xFF) << 24);
    }
    
    /**
     * Converts an integer into binary and stores the result directly into binary data.
     */
    public static void fromInt(int val, byte[] data, int offset) {
	data[offset + 0] = (byte)(val & 0xFF);
	data[offset + 1] = (byte)((val >>> 8) & 0xFF);
	data[offset + 2] = (byte)((val >>> 16) & 0xFF);
	data[offset + 3] = (byte)((val >>> 24) & 0xFF);
    }

    /**
     * Converts binary data back into an unsigned short (0-65535).
     */
    public static int toUnsignedShort(byte data[], int offset) {
	return (data[offset] & 0xFF) + ((data[offset + 1] & 0xFF) << 8);
    }
    
    /**
     * Converts an unsigned short into binary and stores the result directly into binary data.
     */
    public static void fromUnsignedShort(int val, byte[] data, int offset) {
	if(val < 0 || val > 0xFFFF) {
	    throw new IllegalArgumentException("value is not inside range of unsigned short");
	}
	data[offset] = (byte) (val & 0xFF);
	data[offset + 1] = (byte) ((val >>> 8) & 0xFF);
    }
    
    /**
     * Converts binary data back into a String.
     */
    public static String toString(byte data[], int offset) {
	try {
            return new String(data, offset, getStringLength(data, offset), UTF8_ENCODING);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException("UTF-8 encoding not supported on this system");
        }
    }
    
    /**
     * Converts binary data back into a password byte array.
     */
    public static byte[] toPassword(byte data[], int offset) {
        int length = getStringLength(data, offset);
        byte[] passwd = new byte[length];
        if(length > 0) {
            ByteArrays.fillCompletelyFrom(data, offset, passwd);
        }
        return passwd;
    }
    
    /**
     * Converts binary data back into a char array.
     */
    public static char[] toCharArray(byte data[], int offset) {
        try {
            return Helper.byteToCharArray(data, offset, getStringLength(data, offset), UTF8_ENCODING);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException("UTF-8 encoding not supported on this system");
        }
    }
    
    /**
     * Converts a String into binary data.
     */
    public static byte[] fromString(String s) {
	try {
            return ByteArrays.append(s.getBytes(UTF8_ENCODING), new byte[]{STRING_TERMINATOR});
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException("UTF-8 encoding not supported on this system");
        }
    }
    
    /**
     * Converts a password into binary data.
     */
    public static byte[] fromPassword(byte[] s) {
        return ByteArrays.append(s, new byte[]{STRING_TERMINATOR});
    }
    
    /**
     * Converts a char array into binary data.
     */
    public static byte[] fromCharArray(char[] s) {
        try {
            return ByteArrays.append(Helper.charToByteArray(s, 0, s.length, UTF8_ENCODING), new byte[]{STRING_TERMINATOR});
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException("UTF-8 encoding not supported on this system");
        }
    }
    
    /**
     * Returns the length of a String as binary data (number of bytes!). Attention: this can differ from
     * the number of chars, because in UTF-8 it is possible, that a char needs more than one byte (Umlaute)!
     */
    public static int getLength(String s) {
        try {
            return s.getBytes(UTF8_ENCODING).length + 1;
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException("UTF-8 encoding not supported on this system");
        }
    }
    
    /**
     * Returns the length of a char array as binary data (number of bytes!). Attention: this can differ from
     * the number of chars, because in UTF-8 it is possible, that a char needs more than one byte (Umlaute)!
     */
    public static int getLength(char[] s) {
        try {
            return Helper.charToByteArray(s, 0, s.length, UTF8_ENCODING).length + 1;
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException("UTF-8 encoding not supported on this system");
        }
    }
    
    /**
     * Returns the length of a String in bytes (!) that is stored inside binary data. Attention: this can differ from
     * the number of chars, because in UTF-8 it is possible, that a char needs more than one byte (Umlaute)!
     */
    public static int getStringLength(byte[] data, int offset) {
	int len = 0;
	while (data[offset + len] != STRING_TERMINATOR) len++;
	return len;
    }
    
    /**
     * Converts binary data back into an unsigned byte (0-255).
     */
    public static int toUnsignedByte(byte[] data, int offset) {
	return ((int) data[offset] & 0xFF);
    }
    
    /**
     * Converts a hex String into binary data.
     */
    public static byte[] fromHexString(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
}
