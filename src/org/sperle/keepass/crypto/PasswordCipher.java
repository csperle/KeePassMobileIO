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


/**
 * A password cipher is a crypto algorithm, that is able to encrypt and decrypt a KdbEntry password.
 */
public interface PasswordCipher {
    /**
     * Returns the name of the cipher.
     */
    String getName();

    /**
     * Encrypts plain text.
     * @param key the key used for encryption
     * @param plainText plain text to encrypt
     * @return encrypted text
     */
    byte[] encrypt(byte[] key, byte[] plainText);
    
    /**
     * Decrypts encrypted text.
     * @param key the key used for encryption
     * @param cipherText the encrypted text
     * @return plain text
     */
    byte[] decrypt(byte[] key, byte[] cipherText);
}
