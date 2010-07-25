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

package org.sperle.keepass.util;

/**
 * This utility class adapts an String to add the feature of comparison.
 */
public class ComparableString implements org.sperle.keepass.util.Comparable {

    private String adaptee;

    public ComparableString(String s) {
        this.adaptee = s;
    }

    public int compareTo(Object anotherString) {
        return this.adaptee.compareTo(((ComparableString) anotherString).adaptee);
    }

    public String toString() {
        return this.adaptee;
    }

    public boolean equals(Object anotherString) {
        if (this == anotherString)
            return true;
        if (anotherString == null)
            return false;
        if (getClass() != anotherString.getClass())
            return false;
        ComparableString other = (ComparableString) anotherString;
        if (this.adaptee == null) {
            if (other.adaptee != null)
                return false;
        } else if (!this.adaptee.equals(other.adaptee))
            return false;
        return true;
    }

    public int hashCode() {
        return this.adaptee.hashCode();
    }
}
