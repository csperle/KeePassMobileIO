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

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.sperle.keepass.crypto.Hash;
import org.sperle.keepass.monitor.ProgressMonitor;

/**
 * The SHA-256 hash using bouncy castle.
 */
public final class SHA256Hash implements Hash {
    public static final String NAME = "SHA256";
    private static final int DWORD_LENGTH = 4;

    public String getName() {
	return NAME;
    }
    
    public byte[] getHash(byte[][] messages, ProgressMonitor pm) {
	SHA256Digest md = new SHA256Digest();
	if(pm != null) pm.nextStep(sumLength(messages) / DWORD_LENGTH, "pm_hash");
	for (int i = 0; i < messages.length; i++) {
	    md.update(messages[i], 0, messages[i].length, pm);
	    if(pm != null && pm.isCanceled()) return null;
	}
	byte[] hash = new byte[md.getDigestSize()];
	md.doFinal(hash, 0);
	return hash;
    }
    
    private int sumLength(byte[][] messages) {
        int sum = 0;
        for (int i = 0; i < messages.length; i++) {
            sum += messages[i].length;
        }
        return sum;
    }
}
