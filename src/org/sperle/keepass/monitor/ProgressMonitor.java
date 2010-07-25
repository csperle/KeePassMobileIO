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

package org.sperle.keepass.monitor;

/**
 * A progress monitor monitors the progress of a task. It is used to show the task status to the user while
 * loading&decrypting / searching / saving&encrypting of a database and allows the user to cancel the task.
 */
public class ProgressMonitor implements org.bouncycastle.util.ProgressMonitor {
    private int step;
    private int steps;
    private int tick;
    private int ticks;
    private String statusMessage;
    private Object[] statusParams;
    private boolean canceled = false;
    private boolean finished = false;
    
    /**
     * Creates a progress monitor instance with one step.
     */    
    public ProgressMonitor() {
        this(1);
    }
    
    /**
     * Creates a progress monitor instance with the given number of steps.
     */    
    public ProgressMonitor(int steps) {
        setSteps(steps);
    }
    
    /**
     * Returns true if task has started.
     */
    public synchronized boolean started() {
        return step > 0;
    }
    
    /**
     * Sets the status message, that is shown to the user.
     */
    public synchronized void setStatusMessage(String message) {
        this.statusMessage = message;
        this.statusParams = null;
    }

    /**
     * Sets the status message with the given message parameters, that is shown to the user.
     */
    public synchronized void setStatusMessage(String message, Object[] params) {
        this.statusMessage = message;
        this.statusParams = params;
    }
    
    /**
     * Returns the status message, to show to the user.
     */
    public synchronized String getStatusMessage() {
        return statusMessage;
    }
    
    /**
     * Returns the parameters of the status message.
     */
    public synchronized Object[] getStatusParams() {
        return statusParams;
    }
    
    /**
     * Adds one tick while the task runs.
     */
    public synchronized void tick() {
        tick++;
        notifyAll();
    }

    /**
     * Adds the number of ticks while the task runs.
     */
    public synchronized void tick(int ticks) {
        this.tick += ticks;
        notifyAll();
    }
    
    /**
     * Sets the number of steps of this task;
     * @param steps
     */
    public synchronized void setSteps(int steps) {
        if(steps < 1) {
            throw new IllegalArgumentException("task must have at least one step");
        }
        this.step = 0;
        this.steps = steps;
    }
    
    /**
     * Starts next step of the task with the given number of ticks and status message.
     */
    public synchronized void nextStep(int ticks, String status) {
        this.tick = 0;
        this.ticks = ticks;
        step++;
        setStatusMessage(status);
        notifyAll();
    }
    
    /**
     * Returns the progress of the task in percent (0 - 100).
     */
    public synchronized int getProgress() {
        if(step > steps) return 100;
        int oneStepProgress = 100/steps;
        int ticksProgress = (tick < ticks) ? (tick*100/ticks) : 100;
        return (step-1)*oneStepProgress + ticksProgress*oneStepProgress/100;
    }

    /**
     * User cancels the task (using the UI).
     */
    public synchronized void cancel() {
        this.canceled  = true;
        notifyAll();
    }

    /**
     * Returns true, if task was canceled by the user (from UI).
     */
    public synchronized boolean isCanceled() {
        return canceled;
    }
    
    /**
     * Task finished with or without success.
     */
    public synchronized void finish() {
        this.finished = true;
        notifyAll();
    }

    /**
     * Returns true, if task is finished (with or without success).
     */
    public synchronized boolean isFinished() {
        return finished;
    }
}
