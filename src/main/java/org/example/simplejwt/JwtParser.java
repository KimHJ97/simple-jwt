package org.example.simplejwt;

import java.nio.charset.StandardCharsets;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;

import org.example.simplejwt.JWT.Algorithm;
import org.example.simplejwt.JwtAlgorithm.AlgorithmExecutor;
import org.example.simplejwt.JwtComponenet.Header;
import org.example.simplejwt.JwtComponenet.Payload;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public class JwtParser {

	public static SignedKeyProcessor signedKey(String signedKey) {
		return new SignedKeyProcessor(signedKey);
	}

	public static class SignedKeyProcessor {
		private String signedKey;

		public SignedKeyProcessor(String signedKey) {
			if (Objects.isNull(signedKey)) {
				throw new IllegalArgumentException("signedKey cannot be null");
			}

			this.signedKey = signedKey;
		}

		private void validateJsonWebToken(String token) {
			String[] parts = token.split("\\.");
			if (parts.length != 3) {
				throw new IllegalArgumentException("Invalid JWT token");
			}

			String headerBase64 = parts[0];
			String payloadBase64 = parts[1];
			String signature = parts[2];

			try {
				ObjectMapper objectMapper = new ObjectMapper();

				// Header에서 알고리즘 추출
				String headerJson = new String(Base64.getUrlDecoder().decode(headerBase64), StandardCharsets.UTF_8);
				Header header = objectMapper.readValue(headerJson, Header.class);
				Algorithm algorithm = Algorithm.valueOf(header.getAlg());

				// 토큰에 Signature와 SignedKey를 통해 토큰의 Header, Payload로 새롭게 만든 Signature가 동일한지 검증
				AlgorithmExecutor algorithmExecutor = new AlgorithmExecutor(algorithm, signedKey);
				byte[] hash = algorithmExecutor.execute(headerBase64 + "." + payloadBase64);
				String expectedSignature = Base64.getUrlEncoder().withoutPadding().encodeToString(hash);

				if (!expectedSignature.equals(signature)) {
					throw new IllegalArgumentException("Invalid JWT token");
				}

				// 토큰 만료기간 검증
				String payloadJson = new String(Base64.getUrlDecoder().decode(payloadBase64), StandardCharsets.UTF_8);
				Payload payload = new Payload(objectMapper.readValue(payloadJson, Map.class));
				ZonedDateTime expiration = payload.getExpiration(ZoneId.systemDefault());
				if (expiration.isBefore(ZonedDateTime.now())) {
					throw new IllegalArgumentException("The token has expired");
				}
			} catch (JsonProcessingException e) {
				throw new RuntimeException(e);
			}

		}

		public Header header(String token) {
			validateJsonWebToken(token);
			String headerBase64 = token.split("\\.")[0];
			String headerJson = new String(Base64.getUrlDecoder().decode(headerBase64), StandardCharsets.UTF_8);

			try {
				ObjectMapper objectMapper = new ObjectMapper();
				return objectMapper.readValue(headerJson, Header.class);
			} catch (JsonProcessingException e) {
				throw new RuntimeException(e);
			}
		}

		public Payload payload(String token) {
			validateJsonWebToken(token);
			String payloadBase64 = token.split("\\.")[1];
			String payloadJson = new String(Base64.getUrlDecoder().decode(payloadBase64), StandardCharsets.UTF_8);

			try {
				ObjectMapper objectMapper = new ObjectMapper();
				return new Payload(objectMapper.readValue(payloadJson, Map.class));
			} catch (JsonProcessingException e) {
				throw new RuntimeException(e);
			}
		}
	}
}
