package de.trustable.ca3s.quorumProcessor;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import javax.xml.bind.JAXBException;

import org.junit.Test;

import com.fasterxml.jackson.databind.ObjectMapper;

public class QuorumProcessorPersistTest {

	Random random = new Random();

	@Test
	public void testQuorumProcessor() throws GeneralSecurityException, JAXBException, IOException {

		byte[] key = new byte[64];
		random.nextBytes(key);

		Map<Integer, char[]> passwordMap = new HashMap<Integer, char[]>();
		passwordMap.put(0, "treyxcvb0püibvuz".toCharArray());
		passwordMap.put(1, "87r4s54easplkmjn".toCharArray());
		passwordMap.put(2, "34shvTE8z7Lsd5tf".toCharArray());
		passwordMap.put(3, "BS456JHdghjk76jx".toCharArray());

		QuorumProcessor qp = new QuorumProcessor(2, key, passwordMap);

		assertNotNull(qp);

		String jsonContent = writeProcessor(qp);
		
		System.out.println("jsonContent :\n" + jsonContent);

		QuorumProcessor qp2 = readProcessor(jsonContent);

		Map<Integer, char[]> passwordMap1 = new HashMap<Integer, char[]>();
		passwordMap1.put(0, "treyxcvb0püibvuz".toCharArray());
		passwordMap1.put(1, "87r4s54easplkmjn".toCharArray());

		byte[] key1 = qp2.getKey(passwordMap1);
		assertNotNull(key1);
		assertTrue( Arrays.equals(key, key1));

	}

	QuorumProcessor readProcessor(final String content) throws JAXBException, IOException {

		ObjectMapper mapper = new ObjectMapper();

		StringReader sw = new StringReader(content);
		QuorumProcessor qp = mapper.readValue(sw, QuorumProcessor.class);
		return qp;
		
/*		
		JAXBContext jaxbContext = JAXBContext.newInstance(QuorumProcessor.class);

		Unmarshaller jaxbUnmarshaller = jaxbContext.createUnmarshaller();
		try(StringReader sr = new StringReader(content)) {
			QuorumProcessor qp = (QuorumProcessor) jaxbUnmarshaller.unmarshal(sr);
			return qp;
		}
		
		
		ObjectMapper mapper = new ObjectMapper();  
		AnnotationIntrospector introspector = new JAXBIntrospector(mapper.getTypeFactory());
		mapper.setAnnotationIntrospector(introspector);

		String result = mapper.writeValueAsString(user);
*/
		
	}
	
	String writeProcessor(final QuorumProcessor qp) throws JAXBException, IOException {
		
		ObjectMapper mapper = new ObjectMapper();

        StringWriter sw = new StringWriter();
		mapper.writeValue(sw, qp);
        return sw.toString();

/*		
		JAXBContext jaxbContext = JAXBContext.newInstance(QuorumProcessor.class);
        Marshaller jaxbMarshaller = jaxbContext.createMarshaller();

        // To format JSON
        jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
         
        //Set JSON type
//        jaxbMarshaller.setProperty(MarshallerProperties.MEDIA_TYPE, "application/json");
//        jaxbMarshaller.setProperty(MarshallerProperties.JSON_INCLUDE_ROOT, true);

        //Print JSON String to Console
        StringWriter sw = new StringWriter();
        jaxbMarshaller.marshal(qp, sw);
        return sw.toString();
*/
	}	
}
