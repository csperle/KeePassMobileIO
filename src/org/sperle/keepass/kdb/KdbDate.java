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

import java.util.Calendar;
import java.util.Date;

import org.sperle.keepass.util.BinaryData;

/**
 * Value object for handling dates in KeePassMobile. I figured out, that using
 * "java.util.Date" and "Calendar" to much, does harm performance and memory
 * usage. Therefore I wrote my own simple implementation, to hold date
 * information.
 */
public class KdbDate {
    public static final KdbDate NEVER_EXPIRES = new KdbDate(2999, 12, 28, 23, 59, 59);
    private static transient Calendar cal = Calendar.getInstance();
    private final int year, month, day, hour, minute, second;

    /**
     * Creates a KdbDate object with the given date information. Hour, minutes
     * and seconds are set to zero.
     */
    public KdbDate(int year, int month, int day) {
        this.year = year;
        this.month = month;
        this.day = day;
        this.hour = 0;
        this.minute = 0;
        this.second = 0;
    }

    /**
     * Creates a KdbDate object with the given date information.
     */
    public KdbDate(int year, int month, int day, int hour, int minute, int second) {
        this.year = year;
        this.month = month;
        this.day = day;
        this.hour = hour;
        this.minute = minute;
        this.second = second;
    }

    /**
     * Returns a KdbDate object, that represents now.
     * !!!ATTENTION: THIS METHOD IS VERY PERFORMANCE PROBLEMATIC BECAUSE IT CREATES A DATE THAT CREATES A CALENDARIML!
     */
    public static KdbDate now() {
        synchronized (cal) {
            cal.setTime(new Date());
            return new KdbDate(cal.get(Calendar.YEAR), cal.get(Calendar.MONTH) + 1, cal.get(Calendar.DATE), cal
                    .get(Calendar.HOUR_OF_DAY), cal.get(Calendar.MINUTE), cal.get(Calendar.SECOND));
        }
    }

    /**
     * Converts binary data into a KdbDate object.
     * 
     * Packed date/time structure: Byte bits: 11111111 22222222 33333333
     * 44444444 55555555 Contents : 00YYYYYY YYYYYYMM MMDDDDDH HHHHMMMM MMSSSSSS
     */
    public static KdbDate fromBinaryData(byte[] data, int offset) {
        int ub1 = BinaryData.toUnsignedByte(data, offset);
        int ub2 = BinaryData.toUnsignedByte(data, offset + 1);
        int ub3 = BinaryData.toUnsignedByte(data, offset + 2);
        int ub4 = BinaryData.toUnsignedByte(data, offset + 3);
        int ub5 = BinaryData.toUnsignedByte(data, offset + 4);

        // Unpack 5 byte structure to date and time
        int year = (ub1 << 6) | (ub2 >> 2);
        int month = ((ub2 & 0x03) << 2) | (ub3 >> 6);
        int day = (ub3 >> 1) & 0x1F;
        int hour = ((ub3 & 0x01) << 4) | (ub4 >> 4);
        int minute = ((ub4 & 0x0F) << 2) | (ub5 >> 6);
        int second = ub5 & 0x03F;
        
        // patch from fr@francois.rey.name to fix import issue
        if (year == 0 && month == 0 && day == 0 && hour == 0 && minute == 0 && second == 0) return null;
        return new KdbDate(year, month, day, hour, minute, second);
    }

    /**
     * Converts and stores this KdbDate object into binary data (5 bytes).
     */
    public void toBinaryData(byte[] data, int offset) {
        data[offset] = (byte) ((year >> 6) & 0x3F);
        data[offset + 1] = (byte) (((year & 0x3F) << 2) | ((month >> 2) & 0x03));
        data[offset + 2] = (byte) (((month & 0x03) << 6) | ((day & 0x1F) << 1) | ((hour >> 4) & 0x01));
        data[offset + 3] = (byte) (((hour & 0x0F) << 4) | ((minute >> 2) & 0x0F));
        data[offset + 4] = (byte) (((minute & 0x03) << 6) | (second & 0x3F));
    }

    /**
     * Converts java.util.Date into a KdbDate object.
     */
    public static KdbDate fromDate(Date date) {
        synchronized (cal) {
            cal.setTime(date);
            int year = cal.get(Calendar.YEAR);
            int month = cal.get(Calendar.MONTH) + 1;
            int day = cal.get(Calendar.DATE);
            int hour = cal.get(Calendar.HOUR_OF_DAY);
            int minute = cal.get(Calendar.MINUTE);
            int second = cal.get(Calendar.SECOND);
            return new KdbDate(year, month, day, hour, minute, second);
        }
    }

    /**
     * Converts this KdbDate into a java.util.Date object.
     * !!!ATTENTION: THIS METHOD IS VERY PERFORMANCE PROBLEMATIC BECAUSE IT CREATES A DATE THAT CREATES A CALENDARIML!
     */
    public Date toDate() {
        synchronized (cal) {
            cal.set(Calendar.YEAR, year);
            cal.set(Calendar.MONTH, month - 1);
            cal.set(Calendar.DATE, day);
            cal.set(Calendar.HOUR_OF_DAY, hour);
            cal.set(Calendar.MINUTE, minute);
            cal.set(Calendar.SECOND, second);
            cal.set(Calendar.MILLISECOND, 0);
            return cal.getTime();
        }
    }

    /**
     * Checks if this a valid date.
     */
    public boolean isValid() {
        try {
            toDate();
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Returns the year of this date.
     */
    public int getYear() {
        return year;
    }

    /**
     * Returns the month (1-12) of this date.
     */
    public int getMonth() {
        return month;
    }

    /**
     * Returns the day (1-31) of this date.
     */
    public int getDay() {
        return day;
    }

    /**
     * Returns the hour (0-14) of this date.
     */
    public int getHour() {
        return hour;
    }

    /**
     * Returns the minute (0-60) of this date.
     */
    public int getMinute() {
        return minute;
    }

    /**
     * Returns the second (0-60) of this date.
     */
    public int getSecond() {
        return second;
    }

    /**
     * Returns true, if this date is before the given date.
     * 
     * @param other the date to compare to
     */
    public boolean before(KdbDate other) {
        if (year < other.year)
            return true;
        if (year == other.year) {
            if (month < other.month)
                return true;
            if (month == other.month) {
                if (day < other.day)
                    return true;
                if (day == other.day) {
                    if (hour < other.hour)
                        return true;
                    if (hour == other.hour) {
                        if (minute < other.minute)
                            return true;
                        if (minute == other.minute) {
                            if (second < other.second)
                                return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    /**
     * Returns the difference of this and the given date in millis.
     * 
     * @param other the date to compare to
     */
    public long sub(KdbDate other) {
        return toDate().getTime() - other.toDate().getTime();
    }

    public String toString() {
        return day + "." + month + "." + year + " " + hour + ":" + minute + ":" + second;
    }

    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + day;
        result = prime * result + hour;
        result = prime * result + minute;
        result = prime * result + month;
        result = prime * result + second;
        result = prime * result + year;
        return result;
    }

    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        KdbDate other = (KdbDate) obj;
        if (day != other.day)
            return false;
        if (hour != other.hour)
            return false;
        if (minute != other.minute)
            return false;
        if (month != other.month)
            return false;
        if (second != other.second)
            return false;
        if (year != other.year)
            return false;
        return true;
    }

}
