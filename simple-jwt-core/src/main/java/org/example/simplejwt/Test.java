package org.example.simplejwt;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;

import org.example.simplejwt.JwtComponenet.Header;

public class Test {

	public static void main(String[] args) {
		KeyPair keyPair = JWT.generateKeyPair(JWT.Algorithm.ES256, JWT.KeySize.LOW);
		PrivateKey privateKey = keyPair.getPrivate();
		String privateKeyBase64 = JwtSupporter.encodeBase64ToString(privateKey.getEncoded());

		PublicKey publicKey = keyPair.getPublic();
		String publicKeyBase64 = JwtSupporter.encodeBase64ToString(publicKey.getEncoded());

		System.out.println(privateKeyBase64);

		String jwt = JWT.builder()
			.algorithm(JWT.Algorithm.ES256)
			.privateKey(privateKey)
			.issuer("TEST")
			.issuedAt(ZonedDateTime.of(LocalDateTime.of(2099, 12, 31, 23, 59), ZoneId.of("Asia/Seoul")))
			.expiration(ZonedDateTime.of(LocalDateTime.of(2099, 12, 31, 23, 59), ZoneId.of("Asia/Seoul")))
			.build();
		System.out.println(jwt);

		Header header = JWT.parser()
			.publicKey(publicKey)
			.header(jwt);

		System.out.println(header.getTyp());
		System.out.println(header.getAlg());

	}
}
