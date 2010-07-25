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

package org.sperle.keepass.crypto.bc;

import org.bouncycastle.security.SecureRandom;
import org.sperle.keepass.rand.Random;

public class BcRandom implements Random {

    private SecureRandom rand = new SecureRandom();
    
    public int nextInt() {
        return rand.nextInt();
    }
    
    public int nextInt(int max) {
        return rand.nextInt(max);
    }

    public byte[] nextBytes(int length) {
        byte[] id = new byte[length];
        for (int i = 0; i < id.length; i++) {
            id[i] = (byte)(rand.nextInt(256) - 128);
        }
        return id;
    }
}
