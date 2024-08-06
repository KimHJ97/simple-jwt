package org.example.simplejwt;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Map;
import java.util.Objects;

import org.example.simplejwt.JWT.Algorithm;
import org.example.simplejwt.JwtAlgorithm.AlgorithmExecutor;
import org.example.simplejwt.JwtAlgorithm.AlgorithmKeyType;
import org.example.simplejwt.JwtComponenet.Header;
import org.example.simplejwt.JwtComponenet.Payload;
import org.example.simplejwt.JwtException.JwtErrorCode;

public class JwtParser {

	public static SignedKeyProcessor signedKey(String signedKey) {
		return new SignedKeyProcessor(signedKey);
	}

	public static SignedKeyProcessor publicKey(PublicKey publicKey) {
		return new SignedKeyProcessor(JwtSupporter.encodeBase64ToString(publicKey.getEncoded()));
	}

	public static class SignedKeyProcessor {
		private String signedKey;

		public SignedKeyProcessor(String signedKey) {
			if (Objects.isNull(signedKey)) {
				throw new JwtException(JwtErrorCode.SIGNED_KEY_REQUIRED);
			}

			this.signedKey = signedKey;
		}

		private void validateJsonWebToken(String token) {
			String[] parts = token.split("\\.");
			if (parts.length != 3) {
				throw new JwtException(JwtErrorCode.INVALID_TOKEN);
			}

			String headerBase64 = parts[0];
			String payloadBase64 = parts[1];
			String signature = parts[2];

			// Header에서 알고리즘 추출
			String headerJson = JwtSupporter.decodeBase64ToString(headerBase64, StandardCharsets.UTF_8);
			Header header = JwtSupporter.readValue(headerJson, Header.class);
			Algorithm algorithm = Algorithm.valueOf(header.getAlg());

			// 토큰에 Signature와 SignedKey를 통해 토큰의 Header, Payload로 새롭게 만든 Signature가 동일한지 검증
			AlgorithmExecutor algorithmExecutor = new AlgorithmExecutor(algorithm, signedKey, AlgorithmKeyType.of(algorithm, false));
			if (!algorithmExecutor.verify(headerBase64 + "." + payloadBase64, signature)) {
				throw new JwtException(JwtErrorCode.INVALID_TOKEN);
			}

			// 토큰 만료기간 & 유효시작시간 검증
			String payloadJson = JwtSupporter.decodeBase64ToString(payloadBase64, StandardCharsets.UTF_8);
			Payload payload = new Payload(JwtSupporter.readValue(payloadJson, Map.class));

			ZonedDateTime expiration = payload.getExpiration(ZoneId.systemDefault());
			if (!Objects.isNull(expiration)) {
				if (expiration.isBefore(ZonedDateTime.now())) {
					throw new JwtException(JwtErrorCode.EXPIRED_TOKEN);
				}
			}

			ZonedDateTime notBeforeAt = payload.getNotBeforeAt(ZoneId.systemDefault());
			if (!Objects.isNull(notBeforeAt)) {
				if (notBeforeAt.isAfter(ZonedDateTime.now())) {
					throw new JwtException(JwtErrorCode.NOT_BEFORE_TOKEN);
				}
			}
		}

		public Header header(String token) {
			validateJsonWebToken(token);
			String headerBase64 = token.split("\\.")[0];
			String headerJson = JwtSupporter.decodeBase64ToString(headerBase64, StandardCharsets.UTF_8);

			return JwtSupporter.readValue(headerJson, Header.class);
		}

		public Payload payload(String token) {
			validateJsonWebToken(token);
			String payloadBase64 = token.split("\\.")[1];
			String payloadJson = JwtSupporter.decodeBase64ToString(payloadBase64, StandardCharsets.UTF_8);

			return new Payload(JwtSupporter.readValue(payloadJson, Map.class));
		}
	}
}
