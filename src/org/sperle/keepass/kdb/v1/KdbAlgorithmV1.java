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

/**
 * The algorithm that is used to encrypt/decrypt the V1 database.
 */
final class KdbAlgorithmV1 {

    public static final int FLAG_SHA2 = 1;
    public static final int FLAG_AES = 2;
    public static final int FLAG_ARCFOUR = 4;
    public static final int FLAG_TWOFISH = 8;
    
    private final boolean sha2;
    private final boolean aes;
    private final boolean arc4;
    private final boolean twofish;
    
    /**
     * Creates the standard algorithm scheme.
     */
    public KdbAlgorithmV1() {
        sha2 = true;
        aes = true;
        arc4 = false;
        twofish = false;
    }
    
    /**
     * Creates the algorithm scheme from loaded binary data.
     */
    public KdbAlgorithmV1(int data) {
	sha2 = (data & FLAG_SHA2) != 0;
	aes = (data & FLAG_AES) != 0;
	arc4 = (data & FLAG_ARCFOUR) != 0;
	twofish = (data & FLAG_TWOFISH) != 0;
    }
    
    public boolean isSha2() {
        return sha2;
    }

    public boolean isAes() {
        return aes;
    }

    public boolean isArc4() {
        return arc4;
    }

    public boolean isTwofish() {
        return twofish;
    }
    
    public int toInt() {
        int data = 0;
        data += sha2 ? FLAG_SHA2 : 0;
        data += aes ? FLAG_AES : 0;
        data += arc4 ? FLAG_ARCFOUR : 0;
        data += twofish ? FLAG_TWOFISH : 0;
        return data;
    }
}
