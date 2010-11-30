package org.sperle.keepass.kdb;

import java.util.Calendar;
import java.util.Date;

import org.sperle.keepass.KeePassMobileIOTest;
import org.sperle.keepass.util.ByteArrays;

public class KdbDateTest extends KeePassMobileIOTest {
    
    public KdbDateTest() {
        super(7, "KdbDateTest");
    }

    public void test(int testNumber) throws Throwable {
        switch (testNumber) {
        case 0:testFromBinaryData();break;
        case 1:testToBinaryData();break;
        case 2:testBefore();break;
        case 3:testSub();break;
        case 4:testFromToDate();break;
        case 5:testIsValid();break;
        case 6:testEqualsDate();break;
        default:break;
        }
    }

    public void setUp() throws Exception {
    }

    public void testFromBinaryData() throws Exception {
        assertNull(KdbDate.fromBinaryData(new byte[]{0,0,0,0,0}, 0));
        assertEquals(new KdbDate(2008, 12, 2, 9, 7, 35), KdbDate.fromBinaryData(new byte[]{31, 99, 4, -111, -29}, 0));
        assertEquals(new KdbDate(2008, 12, 12, 22, 29, 41), KdbDate.fromBinaryData(new byte[]{31, 99, 25, 103, 105}, 0));
    }
    
    public void testToBinaryData() throws Exception {
        byte[] result = new byte[5];
        new KdbDate(2008, 12, 2, 9, 7, 35).toBinaryData(result, 0);
        assertTrue(ByteArrays.equals(new byte[]{31, 99, 4, -111, -29}, result));
        new KdbDate(2008, 12, 12, 22, 29, 41).toBinaryData(result, 0);
        assertTrue(ByteArrays.equals(new byte[]{31, 99, 25, 103, 105}, result));
    }
    
    public void testBefore() throws Exception {
        assertTrue(new KdbDate(2009, 04, 30, 07, 32, 10).before(new KdbDate(2010, 04, 30, 07, 32, 10)));
        assertFalse(new KdbDate(2009, 04, 30, 07, 32, 10).before(new KdbDate(2009, 04, 30, 07, 32, 10)));
        assertTrue(new KdbDate(2009, 04, 30, 07, 32, 10).before(new KdbDate(2009, 06, 30, 07, 32, 10)));
        assertTrue(new KdbDate(2009, 04, 30, 07, 32, 10).before(new KdbDate(2009, 04, 30, 07, 32, 11)));
    }
    
    public void testSub() throws Exception {
        assertEquals(15*60*1000, new KdbDate(2009, 04, 30, 07, 47, 10).sub(new KdbDate(2009, 04, 30, 07, 32, 10)));
        assertEquals(0, new KdbDate(2009, 04, 30, 07, 32, 10).sub(new KdbDate(2009, 04, 30, 07, 32, 10)));
        assertEquals(-(24*60*60*1000 + 1000), new KdbDate(2009, 04, 30, 07, 32, 10).sub(new KdbDate(2009, 05, 01, 07, 32, 11)));
    }
    
    public void testFromToDate() throws Exception {
        assertEquals(new KdbDate(2009, 12, 02, 21, 19, 00), KdbDate.fromDate(getDate(2009, 12, 02, 21, 19, 00)));
        assertEquals(getDate(2009, 12, 02, 21, 33, 59), new KdbDate(2009, 12, 02, 21, 33, 59).toDate());
    }
    
    public void testIsValid() throws Exception {
        assertTrue(new KdbDate(2009, 12, 02, 21, 19, 00).isValid());
        assertFalse(new KdbDate(2009, 02, 30, 21, 33, 59).isValid());
    }
    
    public void testEqualsDate() throws Exception {
        assertTrue(new KdbDate(2009, 12, 02, 21, 19, 00).equals(getDate(2009, 12, 02, 21, 19, 00)));
        assertFalse(new KdbDate(2009, 02, 11, 21, 33, 59).equals(getDate(2009, 02, 10, 21, 33, 59)));
    }
    
    private Date getDate(int year, int month, int day, int hour, int minute, int second) {
        Calendar cal = Calendar.getInstance();
        cal.set(Calendar.YEAR, year);
        cal.set(Calendar.MONTH, month - 1);
        cal.set(Calendar.DATE, day);
        cal.set(Calendar.HOUR_OF_DAY, hour);
        cal.set(Calendar.MINUTE, minute);
        cal.set(Calendar.SECOND, second);
        cal.set(Calendar.MILLISECOND, 0);
        return cal.getTime();
    }
}
