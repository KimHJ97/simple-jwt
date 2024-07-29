package org.example.simplejwt;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.fasterxml.jackson.databind.ObjectMapper;

public class Main {

	private static final String HEADER = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
	private static final String SECRET = "your-256-bit-secret";
	private static final ObjectMapper objectMapper = new ObjectMapper();

	public static void main(String[] args) throws Exception {
		// Create Payload
		Map<String, Object> payload = new HashMap<>();
		payload.put("sub", "1234567890");
		payload.put("name", "John Doe");
		payload.put("iat", 1516239022);

		// Generate Token
		String token = generateToken(payload);
		System.out.println("Generated Token: " + token);

		// Verify Token
		boolean isVerified = verifyToken(token);
		System.out.println("Is token verified: " + isVerified);

		// Extract specific value from payload
		String name = extractClaim(token, "name");
		System.out.println("Extracted name: " + name);
	}

	public static String generateToken(Map<String, Object> payload) throws Exception {
		String payloadJson = objectMapper.writeValueAsString(payload);
		String payloadBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(payloadJson.getBytes(
			StandardCharsets.UTF_8));

		String signature = hmacSha256(HEADER + "." + payloadBase64, SECRET);
		return HEADER + "." + payloadBase64 + "." + signature;
	}

	public static boolean verifyToken(String token) throws Exception {
		String[] parts = token.split("\\.");
		if (parts.length != 3) {
			return false;
		}

		String header = parts[0];
		String payload = parts[1];
		String signature = parts[2];

		String expectedSignature = hmacSha256(header + "." + payload, SECRET);
		return expectedSignature.equals(signature);
	}

	public static String extractClaim(String token, String claim) throws Exception {
		String[] parts = token.split("\\.");
		if (parts.length != 3) {
			throw new IllegalArgumentException("Invalid JWT token format");
		}

		String payload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
		Map<String, Object> payloadMap = objectMapper.readValue(payload, Map.class);
		return payloadMap.get(claim).toString();
	}

	private static String hmacSha256(String data, String secret) throws Exception {
		Mac mac = Mac.getInstance("HmacSHA256");
		SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
		mac.init(secretKeySpec);
		byte[] hash = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
		return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
	}
}