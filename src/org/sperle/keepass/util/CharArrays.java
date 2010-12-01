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
 * Helper class with macro methods for the work with char arrays.
 */
public class CharArrays {
    public static final char[] EMPTY_STRING = new char[0];

    /**
     * Copies a char array (source) completely into an other char array (target)
     * at the given offset (and the length of the source array).
     * 
     * @param source char array to copy completely
     * @param target char array to copy into
     * @param offset where the copy in the target array should start
     */
    public static void copyCompletelyTo(char[] source, char[] target, int offset) {
        if (source.length + offset > target.length) {
            throw new IllegalArgumentException("array index out of bound");
        }
        System.arraycopy(source, 0, target, offset, source.length);
    }
    
    /**
     * Returns true, if the given char array equals an empty String("").
     */
    public static boolean equalsEmptyString(char[] s) {
        return equals(s, EMPTY_STRING);
    }
    
    /**
     * Copied from J2SE java.util.Arrays!
     */
    public static boolean equals(char[] a, char[] a2) {
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
}
