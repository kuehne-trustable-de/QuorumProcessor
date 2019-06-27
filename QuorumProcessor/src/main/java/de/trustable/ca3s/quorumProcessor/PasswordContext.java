package de.trustable.ca3s.quorumProcessor;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public class PasswordContext {

	@JsonProperty
	byte[] authSalt;
	
	@JsonProperty
	byte[] authResult;
	
	@JsonProperty
	byte[] keySalt;
	
	@JsonProperty
	byte[] bridge;
	
	public PasswordContext() {}
	
	public PasswordContext(byte[] salt, byte[] bridge){
		this.keySalt = salt.clone();
		this.bridge = bridge.clone();
	}

	public PasswordContext(byte[] keySalt, byte[] bridge, byte[] authSalt){
		this.keySalt = keySalt.clone();
		this.bridge = bridge.clone();
		this.authSalt = authSalt.clone();
	}

	public PasswordContext(byte[] keySalt, byte[] bridge, byte[] authSalt, byte[] authResult){
		this.keySalt = keySalt.clone();
		this.bridge = bridge.clone();
		this.authSalt = authSalt.clone();
		this.authResult = authResult.clone();
	}

	/**
	 * @return the key related salt
	 */
	public byte[] getKeySalt() {
		return keySalt.clone();
	}

	/**
	 * @set the keySalt
	 */
	public void setKeySalt(byte[] keySalt) {
		this.keySalt = keySalt.clone();
	}


	/**
	 * @return the bridge
	 */
	public byte[] getBridge() {
		return bridge.clone();
	}

	/**
	 * @set the bridge
	 */
	public void setBridge(byte[] bridge) {
		this.bridge = bridge.clone();
	}


	/**
	 * @return the authSalt
	 */
	public byte[] getAuthSalt() {
		return authSalt.clone();
	}

	/**
	 * @set the AuthSalt
	 */
	public void setAuthSalt(byte[] authSalt) {
		this.authSalt = authSalt.clone();
	}


	/**
	 * @return the authResult
	 */
	public byte[] getAuthResult() {
		return authResult.clone();
	}
	
	/**
	 * @set the authResult
	 */
	public void setAuthResult(byte[] authResult) {
		this.authResult = authResult.clone();
	}

	public String toString() {
		return "Password Context: authSalt " + aboutArray(authSalt) + 
				" authResult " + aboutArray(authResult) + 
				" keySalt " + aboutArray(keySalt) + 
				" bridge " + aboutArray(bridge);
	}
	
	private String aboutArray( byte[] barr){
		if( barr == null) {
			return " null";
		}else {
			return " " + barr.length + " bytes: " + bytesToHex(barr);
		}
	}
	
    private static String bytesToHex(byte[] bArr) {

        StringBuilder sb = new StringBuilder();
        int len = bArr.length;
        if (len > 16) { len = 16;}
        for (int i = 0; i < len; i++) {
            sb.append(String.format("%02x", bArr[i]));
        }
        return sb.toString();

    }

}
