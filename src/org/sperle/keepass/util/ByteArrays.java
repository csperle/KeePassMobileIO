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

/**
 * Helper class with macro methods for the work with byte arrays.
 */
public class ByteArrays {
    public static final byte[] EMPTY_STRING = new byte[0];
    
    /**
     * Returns true, if the given byte array equals an empty String("").
     */
    public static boolean equalsEmptyString(byte[] s) {
        return equals(s, EMPTY_STRING);
    }
    
    /**
     * Copies a byte array (source) completely into an other byte array (target)
     * at the given offset (and the length of the source array).
     * 
     * @param source byte array to copy completely
     * @param target byte array to copy into
     * @param offset where the copy in the target array should start
     */
    public static void copyCompletelyTo(byte[] source, byte[] target, int offset) {
	if (source.length + offset > target.length) {
	    throw new IllegalArgumentException("array index out of bound");
	}
	System.arraycopy(source, 0, target, offset, source.length);
    }
    
    /**
     * Returns a copy of the given byte array.
     * 
     * @param from byte array to copy 
     * @return a copy of the byte array
     */
    public static byte[] returnCopy(byte[] from) {
        if(from == null) {
            return null;
        }
        byte[] to = new byte[from.length];
        if(from.length > 0) {
            System.arraycopy(from, 0, to, 0, from.length);
        }
        return to;
    }

    /**
     * Copies part of a byte array (source) from the given offset (and the
     * length of the target array) to an other byte array (target) till it is
     * filled completely.
     * 
     * @param source byte array to copy from
     * @param offset where the copy in the source array should start
     * @param target byte array to fill
     */
    public static void fillCompletelyFrom(byte[] source, int offset, byte[] target) {
	if (target.length + offset > source.length) {
	    throw new IllegalArgumentException("array index out of bound");
	}
	System.arraycopy(source, offset, target, 0, target.length);
    }
    
    /**
     * Cuts a array to the given max. length (if length > array.length this method does nothing).
     * @param a array to cut
     * @param length max. length to cut to
     * @return a new array with given max. length
     */
    public static byte[] cut(byte[] a, int length) {
        if (length >= a.length) {
            return a;
        }
        byte[] b = new byte[length];
        System.arraycopy(a, 0, b, 0, length);
        return b;
    }
    
    /**
     * Returns a new array that consists of the content of two arrays.
     * 
     * @param original original array
     * @param append array to append to the original
     * @return new array that consists of the content of the two arrays
     */
    public static byte[] append(byte[] original, byte[] append) {
        return append(original, append, 0, append.length);
    }
    
    /**
     * Returns a new array that consists of the first array appended by a section of a second array.
     * 
     * @param original original array
     * @param append array to append to the original
     * @param offset where the section to append in the second array should start
     * @param length of section to append
     * @return new array that consists of the content of the two arrays
     */
    public static byte[] append(byte[] original, byte[] append, int offset, int length) {
        if (offset + length > append.length) {
            throw new IllegalArgumentException("array index out of bound");
        }
	byte[] result = new byte[original.length + length];
	System.arraycopy(original, 0, result, 0, original.length);
	System.arraycopy(append, offset, result, original.length, length);
	return result;
    }
    
    /**
     * Copied from J2SE java.util.Arrays!
     */
    public static int hashCode(byte elements[]) {
        if (elements == null)
            return 0;

        int result = 1;
        for (int i = 0; i < elements.length; i++)
            result = 31 * result + elements[i];

        return result;
    }
    
    /**
     * Copied from J2SE java.util.Arrays!
     */
    public static boolean equals(byte[] a, byte[] a2) {
        if (a==a2)
            return true;
        if (a==null || a2==null)
            return false;

        int length = a.length;
        if (a2.length != length)
            return false;

        for (int i=0; i<length; i++)
            if (a[i] != a2[i])
                return false;

        return true;
    }
    
    /**
     * Fills a byte array with the given value.
     * 
     * @param target byte array to fill
     * @param with byte value to fill with
     */
    public static void fillCompletelyWith(byte[] target, byte with) {
        if(target != null && target.length > 0) {
            for (int i = 0; i < target.length; i++) {
                target[i] = with;
            }
        }
    }
}
