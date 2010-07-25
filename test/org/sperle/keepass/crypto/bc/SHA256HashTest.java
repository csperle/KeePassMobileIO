package org.sperle.keepass.crypto.bc;

import java.io.UnsupportedEncodingException;

import org.bouncycastle.util.encoders.Hex;
import org.sperle.keepass.KeePassMobileIOTest;

public class SHA256HashTest extends KeePassMobileIOTest {
    private static final String TEST_STRING = "Franz jagt im komplett verwahrlosten Taxi quer durch Bayern ÖÄÜöäüß _@!\"§$%&/()[]=*\\n";
    
    private SHA256Hash sha256;
    
    public SHA256HashTest() {
        super(1, "SHA256HashTest");
    }

    public void test(int testNumber) throws Throwable {
        switch (testNumber) {
        case 0:testGetSHA256Digest();break;
        default:break;
        }
    }
    
    public void setUp() throws Exception {
	sha256 = new SHA256Hash();
    }

    public void testGetSHA256Digest() throws UnsupportedEncodingException {
	assertEquals("437a36a93abaa84e1f7fb2b7027e8801310cbc0beef243f6f761a5c42257d826", 
		new String(Hex.encode(sha256.getHash(new byte[][]{TEST_STRING.getBytes("UTF-8")}, null))));
    }
}
