package org.sperle.keepass.kdb.v1;

import org.sperle.keepass.KeePassMobileIOTest;

public class KdbAlgorithmV1Test extends KeePassMobileIOTest {

    public KdbAlgorithmV1Test() {
        super(2, "KdbAlgorithmV1Test");
    }

    public void test(int testNumber) throws Throwable {
        switch (testNumber) {
        case 0:testAlgorithms();break;
        case 1:testToInt();break;
        default:break;
        }
    }

    public void testAlgorithms() {
	KdbAlgorithmV1 algorithm = new KdbAlgorithmV1(0);
	assertFalse(algorithm.isSha2());
	assertFalse(algorithm.isAes());
	assertFalse(algorithm.isArc4());
	assertFalse(algorithm.isTwofish());
	
	algorithm = new KdbAlgorithmV1(1);
	assertTrue(algorithm.isSha2());
	assertFalse(algorithm.isAes());
	assertFalse(algorithm.isArc4());
	assertFalse(algorithm.isTwofish());
	
	algorithm = new KdbAlgorithmV1(2);
	assertFalse(algorithm.isSha2());
	assertTrue(algorithm.isAes());
	assertFalse(algorithm.isArc4());
	assertFalse(algorithm.isTwofish());
	
	algorithm = new KdbAlgorithmV1(4);
	assertFalse(algorithm.isSha2());
	assertFalse(algorithm.isAes());
	assertTrue(algorithm.isArc4());
	assertFalse(algorithm.isTwofish());
	
	algorithm = new KdbAlgorithmV1(8);
	assertFalse(algorithm.isSha2());
	assertFalse(algorithm.isAes());
	assertFalse(algorithm.isArc4());
	assertTrue(algorithm.isTwofish());
	
	algorithm = new KdbAlgorithmV1(15);
	assertTrue(algorithm.isSha2());
	assertTrue(algorithm.isAes());
	assertTrue(algorithm.isArc4());
	assertTrue(algorithm.isTwofish());
    }
    
    public void testToInt() {
        assertEquals(0, new KdbAlgorithmV1(0).toInt());
        assertEquals(2, new KdbAlgorithmV1(2).toInt());
        assertEquals(4, new KdbAlgorithmV1(4).toInt());
        assertEquals(8, new KdbAlgorithmV1(8).toInt());
        assertEquals(15, new KdbAlgorithmV1(15).toInt());
    }
}
