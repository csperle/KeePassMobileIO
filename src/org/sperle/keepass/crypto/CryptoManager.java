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

package org.sperle.keepass.crypto;

import java.util.Hashtable;

import org.sperle.keepass.rand.Random;

/**
 * The crypto manager manages the hash and cipher algorithms that are supported
 * by this KeePassIO distribution. Dev: CryptoManager works implementation
 * independent and therefore does not need an interface.
 */
public class CryptoManager {

    private final Random rand;
    
    private Hashtable hashs = new Hashtable();
    private Hashtable kdbCiphers = new Hashtable();
    private Hashtable passwordCiphers = new Hashtable();
    
    public CryptoManager(Random rand) {
        this.rand = rand;
    }
    
    /**
     * Add a supported hash algorithm.
     */
    public void addHash(Hash hash) {
        hashs.put(hash.getName(), hash);
    }

    /**
     * Returns a supported hash algorithm by name.
     */
    public Hash getHash(String name) {
        return (Hash)hashs.get(name);
    }

    /**
     * Add a supported KeePassDB cipher algorithm.
     */
    public void addKdbCipher(KdbCipher kdbCipher) {
        kdbCiphers.put(kdbCipher.getName(), kdbCipher);
    }

    /**
     * Returns a supported KeePassDB cipher algorithm by name.
     */
    public KdbCipher getKdbCipher(String name) {
        return (KdbCipher)kdbCiphers.get(name);
    }
    
    /**
     * Add a supported password cipher algorithm.
     */
    public void addPasswordCipher(PasswordCipher passwordCipher) {
        passwordCiphers.put(passwordCipher.getName(), passwordCipher);
    }

    /**
     * Returns a freshly initialized supported password cipher algorithm by name.
     */
    public PasswordCipher getPasswordCipher(String name) {
        PasswordCipher cipher = (PasswordCipher)passwordCiphers.get(name);
        if(cipher != null) {
            cipher.init(rand.nextBytes(cipher.getKeyLength()));
        }
        return cipher;
    }
}
