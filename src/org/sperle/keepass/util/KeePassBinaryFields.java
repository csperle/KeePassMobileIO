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

import org.sperle.keepass.kdb.KdbDate;

/**
 * This class takes care of the correct conversion from KeePass database values
 * to KeePass binary database fields and vice versa. Read 'DbFormat.txt' for
 * KeePass DB structure.
 */
public class KeePassBinaryFields {
    public static final int INTEGER_FIELDSIZE = 4;
    public static final int UNSIGNED_SHORT_FIELDSIZE = 2;
    public static final int DATE_FIELDSIZE = 5;
    public static final int TERMINATOR_FIELDSIZE = 0;
    public static final int GROUP_TERMINATOR = 0xFFFF;
    public static final int ENTRY_TERMINATOR = 0xFFFF;
    
    /**
     * Converts an integer into a KeePass binary field array.
     */
    public static byte[] fromInt(int type, int value) {
        byte[] field = new byte[10];
        BinaryData.fromUnsignedShort(type, field, 0);
        BinaryData.fromInt(INTEGER_FIELDSIZE, field, 2);
        BinaryData.fromInt(value, field, 6);
        return field;
    }
    
    /**
     * Converts an unsigned short into a KeePass binary field array.
     */
    public static byte[] fromUnsignedShort(int type, int value) {
        byte[] field = new byte[8];
        BinaryData.fromUnsignedShort(type, field, 0);
        BinaryData.fromInt(UNSIGNED_SHORT_FIELDSIZE, field, 2);
        BinaryData.fromUnsignedShort(value, field, 6);
        return field;
    }
    
    /**
     * Converts a String into a KeePass binary field array.
     */
    public static byte[] fromString(int type, String value) {
        byte[] field = new byte[6];
        BinaryData.fromUnsignedShort(type, field, 0);
        BinaryData.fromInt(BinaryData.getLength(value), field, 2);
        return ByteArrays.append(field, BinaryData.fromString(value));
    }
    
    /**
     * Converts a Date into a KeePass binary field array.
     */
    public static byte[] fromDate(int type, KdbDate value) {
        byte[] field = new byte[11];
        BinaryData.fromUnsignedShort(type, field, 0);
        BinaryData.fromInt(DATE_FIELDSIZE, field, 2);
        value.toBinaryData(field, 6);
        return field;
    }
    
    /**
     * Converts binary data into a KeePass binary field array.
     */
    public static byte[] fromByteArray(int type, byte[] value) {
        byte[] field = new byte[6];
        BinaryData.fromUnsignedShort(type, field, 0);
        BinaryData.fromInt(value.length, field, 2);
        return ByteArrays.append(field, value);
    }
    
    /**
     * Returns the KeePass binary field array that terminates the group field.
     */
    public static byte[] groupTerminator() {
        byte[] field = new byte[6];
        BinaryData.fromUnsignedShort(GROUP_TERMINATOR, field, 0);
        BinaryData.fromInt(TERMINATOR_FIELDSIZE, field, 2);
        return field;
    }
    
    /**
     * Returns the KeePass binary field array that terminates the entry field.
     */
    public static byte[] entryTerminator() {
        byte[] field = new byte[6];
        BinaryData.fromUnsignedShort(ENTRY_TERMINATOR, field, 0);
        BinaryData.fromInt(TERMINATOR_FIELDSIZE, field, 2);
        return field;
    }
}
