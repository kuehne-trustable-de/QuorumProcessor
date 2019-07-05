package de.trustable.ca3s.quorumProcessor;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.xml.bind.annotation.XmlRootElement;

import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * QuorumProcessor
 *
 */
@XmlRootElement(name = "quorumProcessor")
public class QuorumProcessor {

	@JsonProperty
	int N;
	
	@JsonProperty
	int M;
	
	@JsonProperty
	int keyLength;
	
	@JsonProperty
	Map<Integer,PasswordContext> pwCtxMap;

	@JsonProperty
	Map<String, byte[]> quorumKeyMap;
	
	@JsonProperty
	byte[] groupedPasswordSalt = {0,1,2,3,4};
	
	SecureRandom random = new SecureRandom();

	
	final static String PBKDF_ALGO = "PBKDF2WithHmacSHA256";
	final static int PBKDF_SALT_BYTES = 8;
	final static int PBKDF_LENGTH = 32;
	final static int PBKDF_ITERATIONS = 10000;

	SecretKeyFactory skf;

	private static org.slf4j.Logger log = LoggerFactory.getLogger(QuorumProcessor.class);
	
	public QuorumProcessor() throws GeneralSecurityException {
		skf = SecretKeyFactory.getInstance(PBKDF_ALGO);
	}

	public QuorumProcessor(int N, byte[] key, Map<Integer, char[]> passwordMap) throws GeneralSecurityException {

		this();

		if( N == 1 ) {
			log.warn("A quorum of 1 renders the QuorumProcessor somehow useless!");
		}
		
		this.N = N;

		if( key == null) {
			throw new InvalidParameterException("The key MUST NOT be null");
		}
		
		if( key.length < 7) {
			throw new InvalidParameterException("The key MUST have a significant length (>= 8 bytes)");
		}
		
		keyLength = key.length;

		
		M = passwordMap.size();
		if( M < 2) {
			throw new InvalidParameterException("A member count < 2 renders the QuorumProcessor somehow useless!");
		}

		if( N >= M ) {
			throw new InvalidParameterException("The member count MUST be bigger than the quorum!!");
		}

		log.debug("initializing QuorumProcessor for " + N + " out of " + M);
		
//		initializePWCtxMap(M);
		pwCtxMap = new HashMap<Integer,PasswordContext>();

		Map<Integer, byte[]> derivedPasswordMap = buildDerivedKeyMap(passwordMap);
		
		buildResultMap(key, derivedPasswordMap);

		
	}


	/**
	 * 
	 * @param passwordMap
	 * @return
	 * @throws GeneralSecurityException
	 */
	Map<Integer, byte[]> buildDerivedKeyMap(Map<Integer, char[]> passwordMap) throws GeneralSecurityException{

		Map<Integer, byte[]> derivedKeyMap = new HashMap<Integer, byte[]>();
		
		for(Integer passIdx : passwordMap.keySet() ) {

			// initialize the slats and the bridge
			byte[] saltBytes = new byte[PBKDF_SALT_BYTES];
			random.nextBytes(saltBytes);
			byte[] authSaltBytes = new byte[PBKDF_SALT_BYTES];
			random.nextBytes(authSaltBytes);
			byte[] bridgeBytes = new byte[PBKDF_LENGTH];
			random.nextBytes(bridgeBytes);

			// calculate the map entry
			char[] pw = passwordMap.get(passIdx);
			byte[] keyHash = hashPassword(pw, saltBytes, PBKDF_ITERATIONS, PBKDF_LENGTH);
			derivedKeyMap.put(passIdx, xor(keyHash, bridgeBytes));
			
			// build the result for the password verification
			byte[] authResult = hashPassword(pw, authSaltBytes, PBKDF_ITERATIONS, PBKDF_LENGTH);
			
			// save the password ctx
			pwCtxMap.put(passIdx, new PasswordContext(saltBytes, bridgeBytes, authSaltBytes, authResult));

			log.debug("setAuthResult for key " + passIdx + "': " + authResult.length + " ");

		}
		
		return derivedKeyMap;
	}
	
	/**
	 * 
	 * @param password
	 * @param pwCtx.getKeySalt()
	 * @return
	 * @throws GeneralSecurityException
	 */
	byte[] hashPassword(final char[] password, final byte[] salt, int iterations, int resultLen ) throws GeneralSecurityException {

		PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, resultLen*8);
		SecretKey key = skf.generateSecret(spec);
		return key.getEncoded();
		
	}
	
	byte[] hashPassword(final byte[] bArr, final byte[] salt, int iterations, int resultLen ) throws GeneralSecurityException {

		String s = bytesToHex(bArr);
		return hashPassword(s.toCharArray(), salt, iterations, resultLen);
	}
	
	void buildResultMap(byte[] key, Map<Integer, byte[]> derivedPasswordMap) throws GeneralSecurityException{
		
		quorumKeyMap = new HashMap<String, byte[]>();
		buildResultMap(key, derivedPasswordMap, new ArrayList<byte[]>(), "Q", 0, 1 );
	}
	
	void buildResultMap(byte[] key, Map<Integer, byte[]> derivedPasswordMap, ArrayList<byte[]> partList, String index, int start, int level ) throws GeneralSecurityException{

		log.debug("buildResultMap for level " + level + ", M = " + M);

		for( int i = start; i < M; i++) {

			String currentIndex = index + "-" + i;

			ArrayList<byte[]> newParts = new ArrayList<byte[]> (partList);
			byte[] pwArr = derivedPasswordMap.get(i);
			newParts.add(pwArr);

			if( level == N) {

				log.info("currentIndex " + currentIndex + ", pushing pw " + bytesToHex(pwArr));

				MessageDigest digest = MessageDigest.getInstance("SHA-256");
				log.debug("parts has #" + newParts.size() + " elements");
				for( byte[] bArr: newParts) {
					log.debug("digest pw " + bytesToHex(pwArr));
					digest.update(bArr);
				}
				
				byte[] digestOfPW = hashPassword(digest.digest(), groupedPasswordSalt, 1, this.keyLength );
			    byte[] quorumBridge = xor(digestOfPW, key);

				quorumKeyMap.put(currentIndex, quorumBridge);
				log.debug("quorum item added for " + currentIndex);
			}else {				
				buildResultMap(key, derivedPasswordMap, newParts, currentIndex, i + 1, level + 1 );		
			}
		}
	}
	
	public byte[] getKey(Map<Integer, char[]> passwordInMap) throws GeneralSecurityException {

		int inMapSize = passwordInMap.size();
		if( inMapSize != N) {
			throw new InvalidParameterException("The number of passwords provided MUST match the quorum " + inMapSize + " != " + N + "!");
		}

		for(Integer key : passwordInMap.keySet() ) {
			testPassword(key, passwordInMap.get(key));
		}
		
		String index = "Q";

		MessageDigest digest = MessageDigest.getInstance("SHA-256");

//		for(Integer key : passwordInMap.keySet() ) {
		for(int i = 0; i < M; i++ ) {
			
			Integer mapIdx = new Integer(i);
			if( passwordInMap.containsKey(mapIdx )) {
				index += "-" + mapIdx ;
				PasswordContext pwCtx = pwCtxMap.get(mapIdx );
				byte[] bArr = hashPassword(passwordInMap.get(mapIdx), pwCtx.getKeySalt(),PBKDF_ITERATIONS, PBKDF_LENGTH);
				
				digest.update(xor(bArr, pwCtx.getBridge()));
			}
		}
		
		byte[] digestOfPW = hashPassword(digest.digest(), groupedPasswordSalt, 1, this.keyLength );
		log.debug("lookup key for " + index);

		byte[] quorumKey = quorumKeyMap.get(index);
		if( quorumKey == null ) {
			throw new GeneralSecurityException("Not quorum key found for '" + index + "'!");
		}
		
		return xor(digestOfPW, quorumKey);
	}
	
	/**
	 * 
	 * @param n
	 * @param password
	 * @throws GeneralSecurityException
	 */
	public void testPassword(Integer n, char[] password) throws GeneralSecurityException {
		PasswordContext pwCtx = pwCtxMap.get(n);
		byte[] bArr = hashPassword(password, pwCtx.getAuthSalt(), PBKDF_ITERATIONS, PBKDF_LENGTH);
		if( !Arrays.equals(bArr, pwCtx.getAuthResult())) {
			log.info("testPassword for key " + n + "': " + bArr.length + " / " + pwCtx.getAuthResult().length );
			log.info("testPassword for key " + n + "': " + bArr.length + " " + pwCtx);
			
			throw new GeneralSecurityException("password mismatch");
		}
	}
	
	public void changePassword(Integer passIdx, char[] oldPassword, char[] newPassword) throws GeneralSecurityException {

		testPassword(passIdx, oldPassword);

		PasswordContext pwCtx = pwCtxMap.get(passIdx);
		byte[] bOldArr = hashPassword(oldPassword, pwCtx.getKeySalt(), PBKDF_ITERATIONS, PBKDF_LENGTH);
		
		byte[] newSaltBytes = new byte[PBKDF_SALT_BYTES];
		random.nextBytes(newSaltBytes);

		byte[] bNewArr = hashPassword(newPassword, newSaltBytes, PBKDF_ITERATIONS, PBKDF_LENGTH);
		byte[] bNewBridge = xor(xor(bOldArr, pwCtx.getBridge()), bNewArr);
		
		byte[] newAuthSaltBytes = new byte[PBKDF_SALT_BYTES];
		random.nextBytes(newAuthSaltBytes);

		byte[] newAuthResult = hashPassword(newPassword, newAuthSaltBytes, PBKDF_ITERATIONS, PBKDF_LENGTH);
		
		// replace the password ctx
		pwCtxMap.put(passIdx, new PasswordContext(newSaltBytes, bNewBridge, newAuthSaltBytes, newAuthResult));

	}
	
	/**
     * Compute the bitwise XOR of two arrays of bytes. The arrays have to be of
     * same length. No length checking is performed.
     *
     * @param x1 the first array
     * @param x2 the second array
     * @return x1 XOR x2
     */
    public static byte[] xor(byte[] x1, byte[] x2)
    {

		if( x1.length != x2.length) {
			throw new InvalidParameterException("xor: len "+ x1.length +" != " + x2.length);
		}
		
        byte[] out = new byte[x1.length];

        for (int i = x1.length - 1; i >= 0; i--)
        {
            out[i] = (byte)(x1[i] ^ x2[i]);
        }
        return out;
    }

    private static String bytesToHex(byte[] bArr) {

        StringBuilder sb = new StringBuilder();
        if( bArr == null) {
        	sb.append("<null>");
        }else {
	        for (byte b : bArr) {
	            sb.append(String.format("%02x", b));
	        }
        }
        return sb.toString();

    }

}
