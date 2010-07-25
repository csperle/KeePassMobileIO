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

package org.sperle.keepass.kdb;

/**
 * A change listener is called whenever a database item is changed.
 */
public interface KdbChangeListener {
    /**
     * Called before database item is changed.
     * 
     * @param e event information
     */
    void beforeChange(KdbChangeEvent e);
    
    /**
     * Called after database item is changed.
     * 
     * @param e event information
     */
    void afterChange(KdbChangeEvent e);
}
