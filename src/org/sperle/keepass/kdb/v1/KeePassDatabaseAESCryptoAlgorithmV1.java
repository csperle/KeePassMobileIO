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

package org.sperle.keepass.kdb.v1;

import java.io.UnsupportedEncodingException;

import org.sperle.keepass.crypto.KdbCipher;
import org.sperle.keepass.crypto.CryptoManager;
import org.sperle.keepass.crypto.Hash;
import org.sperle.keepass.crypto.KeePassCryptoException;
import org.sperle.keepass.kdb.KeePassDatabase;
import org.sperle.keepass.kdb.KeePassDatabaseCryptoAlgorithm;
import org.sperle.keepass.kdb.PerformanceStatistics;
import org.sperle.keepass.monitor.ProgressMonitor;

/**
 * This crypto algorithm knows how to encrypt/decrypt V1 databases with AES
 * cipher.
 */
public class KeePassDatabaseAESCryptoAlgorithmV1 implements KeePassDatabaseCryptoAlgorithm {

    private Hash sha256;
    private KdbCipher aes;

    public KeePassDatabaseAESCryptoAlgorithmV1(CryptoManager cryptoManager) {
        sha256 = cryptoManager.getHash("SHA256");
        aes = cryptoManager.getKdbCipher("AES");

        if (sha256 == null || aes == null) {
            throw new IllegalStateException("SHA-256/AES not supported");
        }
    }

    public String getName() {
        return "SHA-256/AES";
    }

    public boolean canHandle(KeePassDatabase kdb) {
        if (kdb instanceof KeePassDatabaseV1) {
            return ((KeePassDatabaseV1) kdb).getAlgorithm().isSha2()
                    && ((KeePassDatabaseV1) kdb).getAlgorithm().isAes();
        } else {
            return false;
        }
    }

    public byte[] decrypt(byte[] encryptedContentData, byte[] masterSeed, byte[] masterSeed2, int numKeyEncRounds,
            byte[] encryptionIV, String masterPassword, byte[] keyFile, PerformanceStatistics ps, ProgressMonitor pm) throws KeePassCryptoException {
        if (masterPassword == null && keyFile == null) {
            throw new IllegalArgumentException("master password and key file null");
        }
        
        byte[] passwordKey = getPasswordKey(masterPassword, keyFile);
        
        long start = System.currentTimeMillis();
        byte[] masterKey = encryptMasterKey(masterSeed, masterSeed2, numKeyEncRounds, passwordKey, pm);
        if (masterKey == null) return null; // user canceled
        ps.setMasterKeyEncryptionTime(System.currentTimeMillis() - start);
        
        start = System.currentTimeMillis();
        byte[] decrypted = aes.decrypt(masterKey, encryptedContentData, encryptionIV, pm);
        ps.setDecryptionTime(System.currentTimeMillis() - start);
        
        return decrypted;
    }

    public byte[] encrypt(byte[] plainContentData, byte[] masterSeed, byte[] masterSeed2, int numKeyEncRounds,
            byte[] encryptionIV, String masterPassword, byte[] keyFile, ProgressMonitor pm) throws KeePassCryptoException {
        if (masterPassword == null && keyFile == null) {
            throw new IllegalArgumentException("master password and key file null");
        }
        
        byte[] passwordKey = getPasswordKey(masterPassword, keyFile);
        
        byte[] masterKey = encryptMasterKey(masterSeed, masterSeed2, numKeyEncRounds, passwordKey, pm);
        if (masterKey == null) return null; // user canceled
        
        return aes.encrypt(masterKey, plainContentData, encryptionIV, 1, true, pm);
    }

    private byte[] getPasswordKey(String masterPassword, byte[] keyFile) {
        byte[] passwordKey;
        if(keyFile == null) {
            passwordKey = sha256.getHash(new byte[][] { getEncodedMasterPassword(masterPassword) }, null);
        } else if(masterPassword == null) {
            passwordKey = keyFile;
        } else { // password + key file
            passwordKey = sha256.getHash(new byte[][] { getEncodedMasterPassword(masterPassword) }, null);
            passwordKey = sha256.getHash(new byte[][] { passwordKey, keyFile }, null);
        }
        return passwordKey;
    }
    
    private byte[] getEncodedMasterPassword(String masterPassword) {
        byte[] encMasterPassword = null;
        try {
            encMasterPassword = masterPassword.getBytes(getCorrectPasswordEncoding());
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace(); // Can only happen during development
        }
        return encMasterPassword;
    }

    /**
     * Attention: password encoding is ISO-8859-(1-9) -> depending on the system.
     * Dev problem (eg. when running the tests): Linux returns "UTF-8" as standard encoding!
     */
    private String getCorrectPasswordEncoding() {
        String encoding = System.getProperty("microedition.encoding"); // get system encoding
        if(encoding == null || !encoding.startsWith("ISO-8859")) {
            encoding = "ISO-8859-1";
        }
        return encoding;
    }
    
    private byte[] encryptMasterKey(byte[] masterSeed, byte[] masterSeed2, int numKeyEncRounds, byte[] passwordKey, ProgressMonitor pm)
            throws KeePassCryptoException {
        byte[] masterKey = aes.encrypt(masterSeed2, passwordKey, null, numKeyEncRounds, false, pm);
        if (masterKey == null) return null; // user canceled
        masterKey = sha256.getHash(new byte[][] { masterKey }, null);
        masterKey = sha256.getHash(new byte[][] { masterSeed, masterKey }, null);
        return masterKey;
    }
}
