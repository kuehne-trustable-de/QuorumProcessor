package de.trustable.ca3s.quorumProcessor;

import static org.junit.Assert.*;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import org.junit.Test;

public class QuorumProcessorTest {

	Random random = new Random();
	
	@Test
	public void testQuorumProcessor_2_4() throws GeneralSecurityException {

		byte[] key = new byte[32];
		random.nextBytes(key);
		
		Map<Integer, char[]> passwordMap = new HashMap<Integer, char[]>();
		passwordMap.put(0, "treyxcvb0püibvuz".toCharArray());
		passwordMap.put(1, "87r4s54easplkmjn".toCharArray());
		passwordMap.put(2, "34shvTE8z7Lsd5tf".toCharArray());
		passwordMap.put(3, "BS456JHdghjk76jx".toCharArray());

		QuorumProcessor qp = new QuorumProcessor(2, key, passwordMap);
		
		assertNotNull(qp);

		assertFalse( qp.quorumKeyMap.containsKey("Q-0-0"));
		assertFalse( qp.quorumKeyMap.containsKey("Q-1-1"));
		assertFalse( qp.quorumKeyMap.containsKey("Q-2-2"));
		assertFalse( qp.quorumKeyMap.containsKey("Q-3-3"));
		
		Map<Integer, char[]> passwordMap1 = new HashMap<Integer, char[]>();
		passwordMap1.put(0, "treyxcvb0püibvuz".toCharArray());
		passwordMap1.put(1, "87r4s54easplkmjn".toCharArray());

		byte[] key1 = qp.getKey(passwordMap1);
		assertNotNull(key1);
		assertTrue( Arrays.equals(key, key1));
		
		passwordMap1 = new HashMap<Integer, char[]>();
		passwordMap1.put(0, "treyxcvb0püibvuz".toCharArray());
		passwordMap1.put(2, "34shvTE8z7Lsd5tf".toCharArray());

		key1 = qp.getKey(passwordMap1);
		assertNotNull(key1);
		assertTrue( Arrays.equals(key, key1));
		
		Map<Integer, char[]> passwordMap2 = new HashMap<Integer, char[]>();
		passwordMap2.put(0, "Treyxcvb0püibvuz".toCharArray());
		passwordMap2.put(1, "87r4s54easplkmjn".toCharArray());

		try {
			qp.getKey(passwordMap2);
			fail("password mismatch expected");
		}catch(GeneralSecurityException gse) {
			// as expected
		}
		
		// test unordered list
		Map<Integer, char[]> passwordMap3 = new HashMap<Integer, char[]>();
		passwordMap3.put(2, "34shvTE8z7Lsd5tf".toCharArray());
		passwordMap3.put(0, "treyxcvb0püibvuz".toCharArray());

		byte[] key3 = qp.getKey(passwordMap3);
		assertNotNull(key3);
		assertTrue( Arrays.equals(key, key3));

		qp.testPassword(0, passwordMap.get(0));
		qp.testPassword(1, passwordMap.get(1));
		qp.testPassword(2, passwordMap.get(2));
		qp.testPassword(3, passwordMap.get(3));

		try {
			qp.testPassword(0, "00000000000000".toCharArray());
			fail("password mismatch expected");
		}catch(GeneralSecurityException gse) {
			// as expected
		}

		qp.changePassword(0, "treyxcvb0püibvuz".toCharArray(), "Wy0yA9bdvVlA5DyQ".toCharArray());
		
		Map<Integer, char[]> passwordMap4 = new HashMap<Integer, char[]>();
		passwordMap4.put(0, "Wy0yA9bdvVlA5DyQ".toCharArray());
		passwordMap4.put(2, "34shvTE8z7Lsd5tf".toCharArray());

		byte[] key4 = qp.getKey(passwordMap4);
		assertNotNull(key4);
		assertTrue( Arrays.equals(key, key4));
		
	}

	@Test
	public void testQuorumProcessor_4_20() throws GeneralSecurityException {

		int N = 4;
		
		byte[] key = new byte[32];
		random.nextBytes(key);
		
		Map<Integer, char[]> passwordMap = new HashMap<Integer, char[]>();
		
		passwordMap.put(0, "KguxWgNWhXCKBR3K".toCharArray());
		passwordMap.put(1, "VF0SGBMUEfTyfrTD".toCharArray());
		passwordMap.put(2, "eSD9M8JvoFsdEvDB".toCharArray());
		passwordMap.put(3, "L3zcixom78OqjHTG".toCharArray());
		passwordMap.put(4, "iR5wHzx6Mcd/6At".toCharArray());
		passwordMap.put(5, "cw624Ne4T+NFew4Q".toCharArray());
		passwordMap.put(6, "Wy0yA9bdvVlA5DyQ".toCharArray());
		passwordMap.put(7, "KhWzvXA3N2OTRE/7".toCharArray());
		passwordMap.put(8, "+XeC064OEaDQB38j".toCharArray());
		passwordMap.put(9, "a0L2SvOpzCOQQmSF".toCharArray());
		passwordMap.put(10, "zeKZJCRxcfQVLCoD".toCharArray());
		passwordMap.put(11, "Q4g7fsEybNdYMpgr".toCharArray());
		passwordMap.put(12, "k5/M9MC8j7GclTD2".toCharArray());
		passwordMap.put(13, "dYJLXqQxIlIc87hi".toCharArray());
		passwordMap.put(14, "dpw14c0CAwEAAaNR".toCharArray());
		passwordMap.put(15, "ME8wCwYDVR0PBAQD".toCharArray());
		passwordMap.put(16, "AgGGMA8GA1UdEwEB".toCharArray());
		passwordMap.put(17, "/wQFMAMBAf8wHQYD".toCharArray());
		passwordMap.put(18, "VR0OBBYEFFpxc72I".toCharArray());
		passwordMap.put(19, "cIP1BDzqFhjnl6hL".toCharArray());
		
		QuorumProcessor qp = new QuorumProcessor(N, key, passwordMap);
		
		assertNotNull(qp);
		
		assertFalse( qp.quorumKeyMap.containsKey("Q-0-0-0-0"));
		assertFalse( qp.quorumKeyMap.containsKey("Q-1-1-1-1"));
		assertFalse( qp.quorumKeyMap.containsKey("Q-2-2-2-2"));
		assertFalse( qp.quorumKeyMap.containsKey("Q-3-3-3-3"));

		Map<Integer, char[]> passwordMap1 = new HashMap<Integer, char[]>();
		passwordMap1.put(0, "KguxWgNWhXCKBR3K".toCharArray());
		passwordMap1.put(1, "VF0SGBMUEfTyfrTD".toCharArray());
		passwordMap1.put(2, "eSD9M8JvoFsdEvDB".toCharArray());
		passwordMap1.put(3, "L3zcixom78OqjHTG".toCharArray());

		byte[] key1 = qp.getKey(passwordMap1);
		assertNotNull(key1);
		assertTrue( Arrays.equals(key, key1));

		Map<Integer, char[]> passwordMap2 = new HashMap<Integer, char[]>();
		passwordMap2.put(8, "+XeC064OEaDQB38j".toCharArray());
		passwordMap2.put(10, "zeKZJCRxcfQVLCoD".toCharArray());
		passwordMap2.put(17, "/wQFMAMBAf8wHQYD".toCharArray());
		passwordMap2.put(19, "cIP1BDzqFhjnl6hL".toCharArray());

		byte[] key2 = qp.getKey(passwordMap2);
		assertNotNull(key2);
		assertTrue( Arrays.equals(key, key2));

		// test swapped entries
		Map<Integer, char[]> passwordMap3 = new HashMap<Integer, char[]>();
		passwordMap3.put(10, "zeKZJCRxcfQVLCoD".toCharArray());
		passwordMap3.put(17, "/wQFMAMBAf8wHQYD".toCharArray());
		passwordMap3.put(19, "cIP1BDzqFhjnl6hL".toCharArray());
		passwordMap3.put(8, "+XeC064OEaDQB38j".toCharArray());

		byte[] key3 = qp.getKey(passwordMap3);
		assertNotNull(key3);
		assertTrue( Arrays.equals(key, key3));

		// expect a failure 
		Map<Integer, char[]> passwordMap4 = new HashMap<Integer, char[]>();
		passwordMap4.put(10, "zeKZJCRxcfQVLCoD".toCharArray());
		passwordMap4.put(17, "/wQFMAMBAf8wHQYD".toCharArray());
		passwordMap4.put(19, "cIP1BDzqFhjnl6hL".toCharArray());
		passwordMap4.put(8, "-XeC064OEaDQB38j".toCharArray()); //changed one byte
		
		try {
			qp.getKey(passwordMap4);
			fail("password mismatch expected");
		}catch(GeneralSecurityException gse) {
			// as expected
		}

	}
	
	@Test
	public void testQuorumProcessor_longKey() throws GeneralSecurityException {

		byte[] key = new byte[122];
		random.nextBytes(key);
		
		Map<Integer, char[]> passwordMap = new HashMap<Integer, char[]>();
		passwordMap.put(0, "treyxcvb0püibvuz".toCharArray());
		passwordMap.put(1, "87r4s54easplkmjn".toCharArray());
		passwordMap.put(2, "34shvTE8z7Lsd5tf".toCharArray());
		passwordMap.put(3, "BS456JHdghjk76jx".toCharArray());

		QuorumProcessor qp = new QuorumProcessor(2, key, passwordMap);
		
		assertNotNull(qp);

		Map<Integer, char[]> passwordMap1 = new HashMap<Integer, char[]>();
		passwordMap1.put(0, "treyxcvb0püibvuz".toCharArray());
		passwordMap1.put(1, "87r4s54easplkmjn".toCharArray());

		byte[] key1 = qp.getKey(passwordMap1);
		assertNotNull(key1);
		assertTrue( Arrays.equals(key, key1));
		
		passwordMap1 = new HashMap<Integer, char[]>();
		passwordMap1.put(0, "treyxcvb0püibvuz".toCharArray());
		passwordMap1.put(2, "34shvTE8z7Lsd5tf".toCharArray());

		key1 = qp.getKey(passwordMap1);
		assertNotNull(key1);
		assertTrue( Arrays.equals(key, key1));
		
		Map<Integer, char[]> passwordMap2 = new HashMap<Integer, char[]>();
		passwordMap2.put(0, "Treyxcvb0püibvuz".toCharArray());
		passwordMap2.put(1, "87r4s54easplkmjn".toCharArray());

		try {
			qp.getKey(passwordMap2);
			fail("password mismatch expected");
		}catch(GeneralSecurityException gse) {
			// as expected
		}
		
		// test unordered list
		Map<Integer, char[]> passwordMap3 = new HashMap<Integer, char[]>();
		passwordMap3.put(2, "34shvTE8z7Lsd5tf".toCharArray());
		passwordMap3.put(0, "treyxcvb0püibvuz".toCharArray());

		byte[] key3 = qp.getKey(passwordMap3);
		assertNotNull(key3);
		assertTrue( Arrays.equals(key, key3));


	}

	
}
