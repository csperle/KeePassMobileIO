package org.sperle.keepass.util;

import org.sperle.keepass.KeePassMobileIOTest;
import org.sperle.keepass.kdb.KdbDate;

public class KeePassBinaryFieldsTest extends KeePassMobileIOTest {

    public KeePassBinaryFieldsTest() {
        super(8, "KeePassBinaryFieldsTest");
    }

    public void test(int testNumber) throws Throwable {
        switch (testNumber) {
        case 0:testFromInt();break;
        case 1:testFromUnsignedShort();break;
        case 2:testFromString();break;
        case 3:testFromDate();break;
        case 4:testGroupTerminator();break;
        case 5:testEntryTerminator();break;
        case 6:testFromByteArray();break;
        case 7:testFromCharArray();break;
        default:break;
        }
    }

    public void testFromInt() {
	assertTrue(ByteArrays.equals(new byte[]{1, 0, 4, 0, 0, 0, -23, 50, 36, 126}, KeePassBinaryFields.fromInt(1, 2116301545)));
    }
    
    public void testFromUnsignedShort() {
        assertTrue(ByteArrays.equals(new byte[]{11, 0, 2, 0, 0, 0, 15, 39}, KeePassBinaryFields.fromUnsignedShort(11, 9999)));
    }
    
    public void testFromString() {
        assertTrue(ByteArrays.equals(new byte[]{2, 0, 11, 0, 0, 0, 84, 101, 115, 116, 32, 71, 114, 111, 117, 112, 0}, KeePassBinaryFields.fromString(2, "Test Group")));
    }
    
    public void testFromCharArray() {
        assertTrue(ByteArrays.equals(new byte[]{2, 0, 11, 0, 0, 0, 84, 101, 115, 116, 32, 71, 114, 111, 117, 112, 0}, KeePassBinaryFields.fromCharArray(2, "Test Group".toCharArray())));
    }
    
    public void testFromDate() {
        assertTrue(ByteArrays.equals(new byte[]{3, 0, 5, 0, 0, 0, 31, 99, 26, -50, -73}, KeePassBinaryFields.fromDate(3, new KdbDate(2008, 12, 13, 12, 58, 55))));
    }
    
    public void testGroupTerminator() {
        assertTrue(ByteArrays.equals(new byte[]{-1, -1, 0, 0, 0, 0}, KeePassBinaryFields.groupTerminator()));
    }
    
    public void testEntryTerminator() {
        assertTrue(ByteArrays.equals(new byte[]{-1, -1, 0, 0, 0, 0}, KeePassBinaryFields.entryTerminator()));
    }
    
    public void testFromByteArray() {
        assertTrue(ByteArrays.equals(new byte[]{4, 0, 3, 0, 0, 0, 9, -1, 3}, KeePassBinaryFields.fromByteArray(4, new byte[]{9, -1, 3})));
    }
}
