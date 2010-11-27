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

package org.sperle.keepass;

import org.sperle.keepass.crypto.CryptoManager;
import org.sperle.keepass.crypto.bc.AESCipher;
import org.sperle.keepass.crypto.bc.BcRandom;
import org.sperle.keepass.crypto.bc.SHA256Hash;
import org.sperle.keepass.io.IOManager;
import org.sperle.keepass.io.j2me.J2meIOManager;
import org.sperle.keepass.kdb.CloseStrategy;
import org.sperle.keepass.kdb.DoNothingOnCloseStrategy;
import org.sperle.keepass.kdb.KeePassDatabaseCryptoAlgorithm;
import org.sperle.keepass.kdb.KeePassDatabaseManager;
import org.sperle.keepass.kdb.v1.KeePassDatabaseAESCryptoAlgorithmV1;
import org.sperle.keepass.kdb.v1.KeePassDatabaseManagerV1;
import org.sperle.keepass.rand.JdkRandom;
import org.sperle.keepass.rand.Random;

/**
 * Factory class to construct a fully configured KeePassIO instance. Subclass
 * this factory to configure your own KeePassIO instance. This factory can be
 * replaced by the work of a IOC container!
 */
public class KeePassMobileIOFactory {
    
    /**
     * Creates a fully configured KeePassIO instance.
     */
    public KeePassMobileIO create() {
	return createKeePassMobileIO();
    }

    protected KeePassMobileIO createKeePassMobileIO() {
	return new KeePassMobileIO(createKeePassDatabaseManager());
    }

    protected KeePassDatabaseManager createKeePassDatabaseManager() {
        CryptoManager cm = createCryptoManager();
	KeePassDatabaseManagerV1 kdbm = new KeePassDatabaseManagerV1(createIOManager(), cm, createCloseStrategy(), createRandom());
	KeePassDatabaseCryptoAlgorithm[] cryptoAlgorithms = getKeePassDatabaseCryptoAlgorithms(cm);
	for (int i = 0; i < cryptoAlgorithms.length; i++) {
    	    kdbm.registerCryptoAlgorithm(cryptoAlgorithms[i]);
	}
	return kdbm;
    }

    protected CloseStrategy createCloseStrategy() {
        return new DoNothingOnCloseStrategy();
    }

    protected IOManager createIOManager() {
	return new J2meIOManager();
    }
    
    public Random createRandom() {
        if(this.getClass().getName().indexOf(".") > 0) { // class is not obfuscated -> this was started in dev env -> 
            // use normal random to avoid exception "java/lang/NoClassDefFoundError: java/security/SecureRandom: Cannot create class in system package"
            return new JdkRandom();
        } else { // class is obfuscated -> this was started on mobile device -> it is save to use SecureRandom now
            return new BcRandom();
        }
    }
    
    protected CryptoManager createCryptoManager() {
	CryptoManager cm = new CryptoManager();
	cm.addCipher(new AESCipher());
	cm.addHash(new SHA256Hash());
	return cm;
    }
    
    protected KeePassDatabaseCryptoAlgorithm[] getKeePassDatabaseCryptoAlgorithms(CryptoManager cm) {
        KeePassDatabaseCryptoAlgorithm[] algorithms = new KeePassDatabaseCryptoAlgorithm[1];
        algorithms[0] = new KeePassDatabaseAESCryptoAlgorithmV1(cm);
	return algorithms;
    }
}
