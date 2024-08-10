import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Base64;

import javax.crypto.SecretKey;

import org.example.simplejwt.JWT;
import org.example.simplejwt.JWT.Algorithm;
import org.example.simplejwt.JwtComponenet.Payload;

public class JwtIntegrationUsage {

	public static void main(String[] args) {
		generateHmacSHA256Token();
		generateSHA256withRSAToken();
		generateSHA256withECDSAToken();
	}

	public static void generateHmacSHA256Token() {
		// SecretKey 생성
		SecretKey secretKey = JWT.generateSecretKey(Algorithm.HS256);
		String secretKeyBase64 = Base64.getUrlEncoder().encodeToString(secretKey.getEncoded());

		// JWT 토큰 생성
		String token = JWT.builder()
			.algorithm(Algorithm.HS256)    // 필수 입력
			.secretKey(secretKeyBase64)    // 필수 입력
			.subject("JWT 토큰")
			.issuer("홍길동")
			.issuedAt(ZonedDateTime.of(LocalDateTime.of(2099, 12, 31, 23, 59), ZoneId.of("Asia/Seoul")))
			.expiration(ZonedDateTime.of(LocalDateTime.of(2099, 12, 31, 23, 59), ZoneId.of("Asia/Seoul"))) // 만료일 검증시 사용
			.notBeforeAt(ZonedDateTime.of(LocalDateTime.of(2020, 1, 1, 0, 0), ZoneId.of("Asia/Seoul"))) // 유효 시작일 검증시 사용
			.claim("age", 20)
			.claim("authority", "ADMIN")
			.build();

		// 만들어진 JWT 토큰 추출(검증 및 추출)
		Payload payload = JWT.parser().signedKey(secretKeyBase64)
			.payload(token);

		String subject = payload.getSubject();
		String issuer = payload.getIssuer();
		ZonedDateTime expiration = payload.getExpiration(ZoneId.of("Asia/Seoul"));
		int age = payload.getClaim("age", Integer.class);
		String authority = payload.getClaim("authority", String.class);
	}

	public static void generateSHA256withRSAToken() {
		// 키쌍 생성
		KeyPair keyPair = JWT.generateKeyPair(Algorithm.RS256, JWT.KeySize.LOW);
		PrivateKey privateKey = keyPair.getPrivate();    // 해싱할 때 사용
		PublicKey publicKey = keyPair.getPublic();        // 검증할 때 사용

		// JWT 토큰 생성
		String token = JWT.builder()
			.algorithm(Algorithm.RS256)    // 필수 입력
			.privateKey(privateKey)    // 필수 입력
			.subject("JWT 토큰")
			.issuer("홍길동")
			.issuedAt(ZonedDateTime.of(LocalDateTime.of(2099, 12, 31, 23, 59), ZoneId.of("Asia/Seoul")))
			.expiration(ZonedDateTime.of(LocalDateTime.of(2099, 12, 31, 23, 59), ZoneId.of("Asia/Seoul"))) // 만료일 검증시 사용
			.notBeforeAt(ZonedDateTime.of(LocalDateTime.of(2020, 1, 1, 0, 0), ZoneId.of("Asia/Seoul"))) // 유효 시작일 검증시 사용
			.claim("age", 20)
			.claim("authority", "ADMIN")
			.build();

		// 만들어진 JWT 토큰 추출(검증 및 추출)
		Payload payload = JWT.parser().publicKey(publicKey)
			.payload(token);

		String subject = payload.getSubject();
		String issuer = payload.getIssuer();
		ZonedDateTime expiration = payload.getExpiration(ZoneId.of("Asia/Seoul"));
		int age = payload.getClaim("age", Integer.class);
		String authority = payload.getClaim("authority", String.class);
	}

	public static void generateSHA256withECDSAToken() {
		// 키쌍 생성
		KeyPair keyPair = JWT.generateKeyPair(Algorithm.ES256, JWT.KeySize.LOW);
		PrivateKey privateKey = keyPair.getPrivate();    // 해싱할 때 사용
		PublicKey publicKey = keyPair.getPublic();        // 검증할 때 사용

		// JWT 토큰 생성
		String token = JWT.builder()
			.algorithm(Algorithm.ES256)    // 필수 입력
			.privateKey(privateKey)    // 필수 입력
			.subject("JWT 토큰")
			.issuer("홍길동")
			.issuedAt(ZonedDateTime.of(LocalDateTime.of(2099, 12, 31, 23, 59), ZoneId.of("Asia/Seoul")))
			.expiration(ZonedDateTime.of(LocalDateTime.of(2099, 12, 31, 23, 59), ZoneId.of("Asia/Seoul"))) // 만료일 검증시 사용
			.notBeforeAt(ZonedDateTime.of(LocalDateTime.of(2020, 1, 1, 0, 0), ZoneId.of("Asia/Seoul"))) // 유효 시작일 검증시 사용
			.claim("age", 20)
			.claim("authority", "ADMIN")
			.build();

		// 만들어진 JWT 토큰 추출(검증 및 추출)
		Payload payload = JWT.parser().publicKey(publicKey)
			.payload(token);

		String subject = payload.getSubject();
		String issuer = payload.getIssuer();
		ZonedDateTime expiration = payload.getExpiration(ZoneId.of("Asia/Seoul"));
		int age = payload.getClaim("age", Integer.class);
		String authority = payload.getClaim("authority", String.class);
	}
}
