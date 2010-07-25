package org.sperle.keepass;

import jmunit.framework.cldc11.TestSuite;

import org.sperle.keepass.crypto.CryptoManagerTest;
import org.sperle.keepass.crypto.bc.AESCipherTest;
import org.sperle.keepass.crypto.bc.SHA256HashTest;
import org.sperle.keepass.io.j2me.J2meIOManagerTest;
import org.sperle.keepass.kdb.KdbDateTest;
import org.sperle.keepass.kdb.v1.KdbAlgorithmV1Test;
import org.sperle.keepass.kdb.v1.KdbEntryV1Test;
import org.sperle.keepass.kdb.v1.KdbGroupV1Test;
import org.sperle.keepass.kdb.v1.KeePassDatabaseAESCryptoAlgorithmV1Test;
import org.sperle.keepass.kdb.v1.KeePassDatabaseManagerV1Test;
import org.sperle.keepass.kdb.v1.KeePassDatabaseV1Test;
import org.sperle.keepass.monitor.ProgressMonitorTest;
import org.sperle.keepass.util.BinaryDataTest;
import org.sperle.keepass.util.ByteArraysTest;
import org.sperle.keepass.util.KeePassBinaryFieldsTest;

public class KeePassMobileIOTestSuite extends TestSuite {
    public KeePassMobileIOTestSuite() {
        super("KeePassIOTestSuite");
        add(new CryptoManagerTest());
        add(new AESCipherTest());
        add(new SHA256HashTest());
        add(new KdbAlgorithmV1Test());
        add(new J2meIOManagerTest());
        add(new KdbGroupV1Test());
        add(new KdbEntryV1Test());
        add(new KeePassDatabaseAESCryptoAlgorithmV1Test());
        add(new KeePassDatabaseManagerV1Test());
        add(new KeePassDatabaseV1Test());
        add(new ProgressMonitorTest());
        add(new ByteArraysTest());
        add(new BinaryDataTest());
        add(new KeePassBinaryFieldsTest());
        add(new KdbDateTest());
    }
}
