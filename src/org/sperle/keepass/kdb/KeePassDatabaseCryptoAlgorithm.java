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

package org.sperle.keepass.kdb;

import org.sperle.keepass.crypto.KeePassCryptoException;
import org.sperle.keepass.monitor.ProgressMonitor;

/**
 * A crypto algorithm that can encrypt and decrypt some kind of KeePass database.
 */
public interface KeePassDatabaseCryptoAlgorithm {
    /**
     * Returns the name of this kdb crypto algorithm.
     */
    String getName();
    
    /**
     * Encrypts a KeePass database.
     */
    byte[] encrypt(byte[] plainContentData, byte[] masterSeed, byte[] masterSeed2, int numKeyEncRounds, 
	    byte[] encryptionIV, byte[] masterPassword, byte[] keyFile, ProgressMonitor pm) throws KeePassCryptoException;
    
    /**
     * Returns true, if this algorithm can encrypt/decrypt the given KeePass database.
     */
    boolean canHandle(KeePassDatabase kdb);

    /**
     * Decrypts a KeePass database.
     */
    byte[] decrypt(byte[] encryptedContentData, byte[] masterSeed, byte[] masterSeed2, int numKeyEncRounds, 
	    byte[] encryptionIV, byte[] masterPassword, byte[] keyFile, PerformanceStatistics ps, ProgressMonitor pm) throws KeePassCryptoException;
}
