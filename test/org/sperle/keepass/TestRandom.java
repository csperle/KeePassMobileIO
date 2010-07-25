package org.sperle.keepass;

import org.sperle.keepass.rand.Random;

/**
 * Random that uses prepared 'random' numbers to enable testing of 'random' behaviour.
 */
public class TestRandom implements Random
{
    int i;
    int[] randomInt;
    
    public void setRandomInt(int[] randomInt) {
        this.i = 0;
        this.randomInt = randomInt;
    }

    public int nextInt() {
        if(randomInt == null || i >= randomInt.length) {
            throw new IllegalStateException("not enough random numbers provided");
        }
        
        return randomInt[i++];
    }
    
    public int nextInt(int n) {
        return nextInt();
    }

    public byte[] nextBytes(int length) {
        int rand = nextInt();
        byte[] id = new byte[length];
        for (int i = 0; i < id.length; i++) {
            id[i] = (byte)rand;
        }
        return id;
    }
}
