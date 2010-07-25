package org.sperle.keepass.util;

import org.sperle.keepass.KeePassMobileIOTest;


public class ByteArraysTest extends KeePassMobileIOTest {

    public ByteArraysTest() {
        super(7, "ByteArraysTest");
    }

    public void test(int testNumber) throws Throwable {
        switch (testNumber) {
        case 0:testCopyCompletelyTo();break;
        case 1:testCopyCompletelyToOutOfBound();break;
        case 2:testFillCompletelyFrom();break;
        case 3:testFillCompletelyFromOutOfBound();break;
        case 4:testAppend();break;
        case 5:testAppendSection();break;
        case 6:testCut();break;
        default:break;
        }
    }
    
    public void testCopyCompletelyTo() {
	byte[] target = new byte[] {0,0,0};
	ByteArrays.copyCompletelyTo(new byte[] {1}, target, 1);
	assertTrue(ByteArrays.equals(new byte[] {0,1,0}, target));
	
	target = new byte[] {0,0,0};
	ByteArrays.copyCompletelyTo(new byte[] {1,2}, target, 1);
	assertTrue(ByteArrays.equals(new byte[] {0,1,2}, target));
	
	target = new byte[] {0,0,0};
	ByteArrays.copyCompletelyTo(new byte[] {1,2,3}, target, 0);
	assertTrue(ByteArrays.equals(new byte[] {1,2,3}, target));
    }
    
    public void testCopyCompletelyToOutOfBound() throws Exception {
        try {
            byte[] target = new byte[] { 0, 0, 0 };
            ByteArrays.copyCompletelyTo(new byte[] { 1, 2, 3, 4 }, target, 0);
            fail("Should fail with IllegalArgumentException");
        } catch (IllegalArgumentException e) {/* OK */}
    }
    
    public void testFillCompletelyFrom() {
	byte[] target = new byte[3];
	ByteArrays.fillCompletelyFrom(new byte[] {1,2,3,4}, 0, target);
	assertTrue(ByteArrays.equals(new byte[] {1,2,3}, target));
	
	target = new byte[3];
	ByteArrays.fillCompletelyFrom(new byte[] {1,2,3,4}, 1, target);
	assertTrue(ByteArrays.equals(new byte[] {2,3,4}, target));
    }
    
    public void testFillCompletelyFromOutOfBound() throws Exception {
        try {
            byte[] target = new byte[3];
            ByteArrays.fillCompletelyFrom(new byte[] { 1, 2, 3, 4 }, 2, target);
            fail("Should fail with IllegalArgumentException");
        } catch (IllegalArgumentException e) {}
    }
    
    public void testCut() {
        assertTrue(ByteArrays.equals(new byte[0], ByteArrays.cut(new byte[0], 0)));
        assertTrue(ByteArrays.equals(new byte[0], ByteArrays.cut(new byte[] {3}, 0)));
        assertTrue(ByteArrays.equals(new byte[] {3}, ByteArrays.cut(new byte[] {3}, 1)));
        assertTrue(ByteArrays.equals(new byte[] {3}, ByteArrays.cut(new byte[] {3}, 2)));
        assertTrue(ByteArrays.equals(new byte[] {3,4}, ByteArrays.cut(new byte[] {3,4,5}, 2)));
    }
    
    public void testAppend() {
        assertTrue(ByteArrays.equals(new byte[] {3}, ByteArrays.append(new byte[0], new byte[] {3})));
        assertTrue(ByteArrays.equals(new byte[] {1,2}, ByteArrays.append(new byte[] {1,2}, new byte[0])));
        assertTrue(ByteArrays.equals(new byte[] {1,2,3}, ByteArrays.append(new byte[] {1,2}, new byte[] {3})));
    }
    
    public void testAppendSection() {
        assertTrue(ByteArrays.equals(new byte[] {4}, ByteArrays.append(new byte[0], new byte[] {3,4}, 1, 1)));
        assertTrue(ByteArrays.equals(new byte[] {1,2}, ByteArrays.append(new byte[]{1,2}, new byte[0], 0, 0)));
        assertTrue(ByteArrays.equals(new byte[] {1,2,3,4}, ByteArrays.append(new byte[] {1,2}, new byte[] {3,4}, 0, 2)));
        assertTrue(ByteArrays.equals(new byte[] {1,2,4}, ByteArrays.append(new byte[] {1,2}, new byte[] {3,4}, 1, 1)));
    }
    
    public void testAppendSectionOutOfBound() {
        try {
            assertTrue(ByteArrays.equals(new byte[] {1,2,3,4}, ByteArrays.append(new byte[] {1,2}, new byte[] {3,4}, 1, 2)));
            fail("Should fail with IllegalArgumentException");
        } catch (IllegalArgumentException e) {}
    }
}
