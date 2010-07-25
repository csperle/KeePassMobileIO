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

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.sperle.keepass.crypto.Cipher;
import org.sperle.keepass.crypto.KeePassCryptoException;
import org.sperle.keepass.monitor.ProgressMonitor;
import org.sperle.keepass.util.ByteArrays;

/**
 * The AES (Rijndael) cipher using bouncy castle.
 */
public final class AESCipher implements Cipher {
    public static final String NAME = "AES";

    public String getName() {
	return NAME;
    }
    
    public byte[] encrypt(byte[] key, byte[] plainText, byte[] iv, int rounds, boolean padding, ProgressMonitor pm) throws KeePassCryptoException {
	try {
	    BufferedBlockCipher cipher = null;
	    if(padding) {
	        cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()));
	    } else {
	        cipher = new BufferedBlockCipher(new AESEngine());
	    }
	    
	    if(iv != null) cipher.init(true, new ParametersWithIV(new KeyParameter(key), iv));
	    else cipher.init(true, new KeyParameter(key));
	    
	    if(pm != null) {
	        if(rounds == 1) pm.nextStep(plainText.length / cipher.getBlockSize(), "pm_encrypt"); // count length (database)
	        else if (rounds > 1) pm.nextStep(rounds, "pm_encrypt"); // count rounds (master password)
	    }
	    
	    byte[] cipherText = null;
	    if(padding) {
	        cipherText = new byte[cipher.getOutputSize(plainText.length)];
	    } else {
	        cipherText = new byte[plainText.length];
	    }
	    
	    int outLength = cipher.processBytes(plainText, 0, plainText.length, cipherText, 0, rounds == 1 ? pm : null);
	    if(outLength == -1) return null; // user canceled
	    if(rounds > 1) {
	        if(pm != null) pm.tick();
	        for (int i = 1; i < rounds; i++) {
	            outLength = cipher.processBytes(cipherText, 0, cipherText.length, cipherText, 0, null);
	            if(pm != null) {
	                if(pm.isCanceled()) return null;
	                pm.tick();
	            }
	        }
	    }
	    
	    if(padding) cipher.doFinal(cipherText, outLength);
	    return cipherText;
	} catch (Exception e) {
	    throw new KeePassCryptoException("Exception during kdb encryption: " + e.getMessage());
	}
    }
    
    public byte[] decrypt(byte[] key, byte[] cipherText, byte[] iv, ProgressMonitor pm) throws KeePassCryptoException {
	try {
	    BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()));
	    if(iv != null) cipher.init(false, new ParametersWithIV(new KeyParameter(key), iv));
	    else cipher.init(false, new KeyParameter(key));
	    if(pm != null) pm.nextStep(cipherText.length / cipher.getBlockSize(), "pm_decrypt");
	    byte[] plainText = new byte[cipher.getOutputSize(cipherText.length)];
	    int outLength = cipher.processBytes(cipherText, 0, cipherText.length, plainText, 0, pm);
	    if(outLength == -1) return null; // user canceled
	    outLength += cipher.doFinal(plainText, outLength);
	    return (outLength < plainText.length) ? ByteArrays.cut(plainText, outLength) : plainText;
	} catch (Exception e) {
	    throw new KeePassCryptoException("Exception during kdb decryption: " + e.getMessage());
	}
    }
}
