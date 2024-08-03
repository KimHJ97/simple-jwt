package org.example.simplejwt;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import javax.crypto.SecretKey;

import org.example.simplejwt.JWT.Algorithm;
import org.example.simplejwt.JwtComponenet.Header;
import org.example.simplejwt.JwtComponenet.Payload;
import org.example.simplejwt.JwtComponenet.Signature;

public class JwtBuilder {
	private String secretKey;
	private Algorithm algorithm;
	private Map<String, Object> claims = new HashMap<>();

	/* Builder */
	public JwtBuilder secretKey(String secretKey) {
		this.secretKey = secretKey;
		return this;
	}

	public JwtBuilder secretKey(SecretKey secretKey) {
		this.secretKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
		return this;
	}

	public JwtBuilder secretKey(PrivateKey privateKey) {
		this.secretKey = Base64.getEncoder().encodeToString(privateKey.getEncoded());
		return this;
	}

	public JwtBuilder algorithm(Algorithm algorithm) {
		this.algorithm = algorithm;
		return this;
	}

	public JwtBuilder issuer(String issuer) {
		this.claims.put("issuer", issuer);
		return this;
	}

	public JwtBuilder subject(String subject) {
		this.claims.put("subject", subject);
		return this;
	}

	public JwtBuilder audience(String audience) {
		this.claims.put("audience", audience);
		return this;
	}

	public JwtBuilder expiration(ZonedDateTime expiration) {
		this.claims.put("expiration", expiration.toEpochSecond());
		return this;
	}

	public JwtBuilder notBeforeAt(ZonedDateTime notBeforeAt) {
		this.claims.put("notBeforeAt", notBeforeAt.toEpochSecond());
		return this;
	}

	public JwtBuilder issuedAt(ZonedDateTime issuedAt) {
		this.claims.put("issuedAt", issuedAt.toEpochSecond());
		return this;
	}

	public JwtBuilder claim(String key, Object value) {
		this.claims.put(key, value);
		return this;
	}

	public String build() {
		// 1. Validate Required Fields
		this.validateRequiredFields();

		// 2. Create Header
		Header header = new Header(this.algorithm);
		String headerBase64 = JwtSupporter.encodeBase64ToStringWithoutPadding(
			header.toJson().getBytes(StandardCharsets.UTF_8));

		// 3. Create Payload
		Payload payload = new Payload(this.claims);
		String payloadBase64 = JwtSupporter.encodeBase64ToStringWithoutPadding(
			payload.toJson().getBytes(StandardCharsets.UTF_8));

		// 4. Create Signature
		Signature signature = new Signature(headerBase64, payloadBase64, secretKey, algorithm);
		String signatureHashBase64 = JwtSupporter.encodeBase64ToStringWithoutPadding(signature.toHash());

		// 5. Return JWT(HEADER.PAYLOAD.SIGNATURE)
		return headerBase64 + "." + payloadBase64 + "." + signatureHashBase64;
	}

	private void validateRequiredFields() {
		if (Objects.isNull(secretKey)) {
			throw new IllegalArgumentException("secretKey is required");
		}
		if (Objects.isNull(algorithm)) {
			throw new IllegalArgumentException("algorithm is required");
		}
	}

}