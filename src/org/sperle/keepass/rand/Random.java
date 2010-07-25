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

package org.sperle.keepass.rand;

public interface Random {
    /**
     * Generates a random value within the integer range.
     */
    int nextInt();
    
    /**
     * Generates a random integer value between 0 (inclusive) and the specified
     * maximum number (exclusive).
     * 
     * @param max maximum random number (must be positive)
     * 
     * @return random integer between 0 - max
     */
    int nextInt(int max);
    
    /**
     * Generates a byte array of the given length with random numbers.
     */
    byte[] nextBytes(int length);
}
