package org.sperle.keepass.util;

import org.sperle.keepass.KeePassMobileIOTest;

public class BinaryDataTest extends KeePassMobileIOTest {

    public BinaryDataTest() {
        super(8, "BinaryDataTest");
    }

    public void test(int testNumber) throws Throwable {
        switch (testNumber) {
        case 0:testFromInt();break;
        case 1:testToInt();break;
        case 2:testFromUnsignedShort();break;
        case 3:testToUnsignedShort();break;
        case 4:testUnsignedShortNegative();break;
        case 5:testUnsignedShortOutOfRange();break;
        case 6:testString();break;
        case 7:testUnsignedByte();break;
        default:break;
        }
    }

    public void testFromInt() {
	byte[] result = new byte[4];
	BinaryData.fromInt(0, result, 0);
	assertTrue(ByteArrays.equals(new byte[]{0, 0, 0, 0}, result));
	
	BinaryData.fromInt(19, result, 0);
	assertTrue(ByteArrays.equals(new byte[]{19, 0, 0, 0}, result));
    }
    
    public void testToInt() {
	assertEquals(0, BinaryData.toInt(new byte[]{0, 0, 0, 0}, 0));
	
	byte[] result = new byte[4];
	BinaryData.fromInt(567829, result, 0);
	assertEquals(567829, BinaryData.toInt(result, 0));
	
	BinaryData.fromInt(-12351, result, 0);
	assertEquals(-12351, BinaryData.toInt(result, 0));
    }
    
    public void testFromUnsignedShort() {
	byte[] result = new byte[2];
	BinaryData.fromUnsignedShort(0, result, 0);
	assertTrue(ByteArrays.equals(new byte[]{0, 0}, result));
	
	BinaryData.fromUnsignedShort(19, result, 0);
	assertTrue(ByteArrays.equals(new byte[]{19, 0}, result));
    }
    
    public void testToUnsignedShort() {
	assertEquals(0, BinaryData.toUnsignedShort(new byte[]{0, 0}, 0));
	
	byte[] result = new byte[2];
	BinaryData.fromUnsignedShort(9271, result, 0);
	assertEquals(9271, BinaryData.toUnsignedShort(result, 0));
	
	BinaryData.fromUnsignedShort(0, result, 0);
	assertEquals(0, BinaryData.toUnsignedShort(result, 0));
	
	BinaryData.fromUnsignedShort(0xFFFF, result, 0);
	assertEquals(0xFFFF, BinaryData.toUnsignedShort(result, 0));
    }
    
    public void testUnsignedShortNegative() {
        try {
            byte[] result = new byte[2];
            BinaryData.fromUnsignedShort(-1, result, 0);
            fail("Should fail with IllegalArgumentException");
        } catch (IllegalArgumentException e) {}
    }

    public void testUnsignedShortOutOfRange() {
        try {
            byte[] result = new byte[2];
            BinaryData.fromUnsignedShort(0x10000, result, 0);
            fail("Should fail with IllegalArgumentException");
        } catch (IllegalArgumentException e) {}
    }
    
    public void testString() {
	assertEquals(12, BinaryData.getLength("Test Däta!"));
	assertTrue(ByteArrays.equals(new byte[]{84, 101, 115, 116, 32, 68, -61, -92, 116, 97, 33, 0}, BinaryData.fromString("Test Däta!")));
	assertEquals("Test Däta!", BinaryData.toString(new byte[]{84, 101, 115, 116, 32, 68, -61, -92, 116, 97, 33, 0}, 0));
	assertEquals(6, BinaryData.getStringLength(new byte[]{84, 101, 115, 116, 32, 68, -61, -92, 116, 97, 33, 0}, 5));
    }
    
    public void testUnsignedByte() {
	assertEquals(255, BinaryData.toUnsignedByte(new byte[]{-1}, 0));
	assertEquals(128, BinaryData.toUnsignedByte(new byte[]{-128}, 0));
	assertEquals(0, BinaryData.toUnsignedByte(new byte[]{0}, 0));
	assertEquals(127, BinaryData.toUnsignedByte(new byte[]{127}, 0));
    }
}
