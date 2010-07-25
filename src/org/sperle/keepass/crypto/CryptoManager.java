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

/**
 * The crypto manager manages the hash and cipher algorithms that are supported
 * on this KeePassIO distribution. Dev: CryptoManager works implementation
 * independent and therefore does not need an interface.
 */
public class CryptoManager {

    private Hashtable hashs = new Hashtable();
    private Hashtable ciphers = new Hashtable();

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
     * Add a supported cipher algorithm.
     */
    public void addCipher(Cipher cipher) {
        ciphers.put(cipher.getName(), cipher);
    }

    /**
     * Returns a supported cipher algorithm by name.
     */
    public Cipher getCipher(String name) {
        return (Cipher)ciphers.get(name);
    }
}
