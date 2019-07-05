package de.trustable.ca3s.quorumProcessor;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.util.HashMap;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;

public class QPMain {

	private static final String DEFAULT_SECRET = "default-secret";

	public static void main(String[] args) throws Exception {

		boolean initialize = false;

		int n = 0;
		String key = DEFAULT_SECRET;
		Map<Integer, char[]> passwordMap = new HashMap<Integer, char[]>();
		File jsonFile = null;
		
		if( args.length == 0) {
			printInfo();
		}

		for( String arg:args) {
			if( "-I".equalsIgnoreCase(arg) ) {
				initialize = true;
			}
		}
		
		for( int i = 0; i < args.length; i++) {
			String arg = args[i];
			if( "-N".equalsIgnoreCase(arg) ) {
				n = Integer.parseInt(args[i+1]);
				i++;
			}else if( "-K".equalsIgnoreCase(arg)) {
				key = args[i+1];
				i++;
			}else if( "-F".equalsIgnoreCase(arg)) {
				jsonFile = new File(args[i+1]);
				i++;
			}else if (arg.toUpperCase().startsWith("-PW")) {
				int ord = Integer.parseInt(arg.substring(3));
				passwordMap.put(ord, args[i+1].toCharArray());
				i++;
			}else if ("-I".equalsIgnoreCase(arg)) {
				// already processeed
			}else {
				System.err.println("Unexpected argument '" + arg + "'");
			}
		}

		ObjectMapper mapper = new ObjectMapper();

		if( jsonFile == null) {
			System.err.println("JSON filename MUST be present!");
			System.exit(2);
		}
		
		if( initialize ) {
			
			if( key.equals(DEFAULT_SECRET)) {
				System.out.println("key argument not defined, using '"+DEFAULT_SECRET+"' ...");
			}
			
			QuorumProcessor qp = new QuorumProcessor(n, key.getBytes(), passwordMap);
	
	        FileWriter fw = new FileWriter(jsonFile);
			mapper.writeValue(fw, qp);
			fw.close();
		} else {

			FileReader fr = new FileReader(jsonFile);
			QuorumProcessor qp = mapper.readValue(fr, QuorumProcessor.class);
			fr.close();
			System.out.println("retrieved key: " + new String( qp.getKey(passwordMap)));

		}

        
	}

	private static void printInfo() {
		// TODO Auto-generated method stub
		
	}

}
