package org.sperle.keepass.monitor;

import org.sperle.keepass.KeePassMobileIOTest;

public class ProgressMonitorTest extends KeePassMobileIOTest {
    
    private ProgressMonitor pm;
    
    public ProgressMonitorTest() {
        super(2, "ProgressMonitorTest");
    }

    public void test(int testNumber) throws Throwable {
        switch (testNumber) {
        case 0:testOneStep();break;
        case 1:testMoreSteps();break;
        default:break;
        }
    }
    
    public void setUp() throws Exception {
    }
    
    public void testOneStep() {
        pm = new ProgressMonitor(); // one step
        pm.nextStep(100, null);
        assertEquals(0, pm.getProgress());
        
	pm.setStatusMessage("Status Message 1");
	assertEquals("Status Message 1", pm.getStatusMessage());
	
	assertEquals(false, pm.isCanceled());
	for (int i = 1; i <= 100; i++) {
            pm.tick();
            assertEquals(i, pm.getProgress());
            
            if(i == 80) {
                pm.cancel();
                break;
            }
        }
	assertEquals(80, pm.getProgress());
	assertEquals(true, pm.isCanceled());
    }
    
    public void testMoreSteps() {
        pm = new ProgressMonitor(4); // one step
        assertFalse(pm.started());
        pm.nextStep(100, "Step 1");
        assertTrue(pm.started());
        assertEquals(0, pm.getProgress());
        assertEquals("Step 1", pm.getStatusMessage());
        pm.tick(80);
        assertEquals(20, pm.getProgress());
        
        pm.nextStep(50, "Step 2");
        assertEquals(25, pm.getProgress());
        assertEquals("Step 2", pm.getStatusMessage());
        pm.tick(30);
        assertEquals(40, pm.getProgress());
        pm.tick(30);
        assertEquals(50, pm.getProgress());
        
        pm.nextStep(50, "Step 3");
        assertEquals(50, pm.getProgress());
        assertEquals("Step 3", pm.getStatusMessage());
        
        pm.nextStep(50, "Step 4");
        assertEquals(75, pm.getProgress());
        assertEquals("Step 4", pm.getStatusMessage());
        pm.tick(50);
        assertEquals(100, pm.getProgress());
        
        pm.nextStep(100, "Illegal Step 5");
        pm.tick(50);
        assertEquals(100, pm.getProgress());
    }
}
