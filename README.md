# simple-jwt

## Features

 - Generate JSON Web Token
 - Parse JSON Web Token (extract header and payload)
 - Validate JSON Web Token
 - Generate HmacSHA SecretKey
 - Generate RSA, EC key pairs (private key and public key)

## How to Start

 - Maven
```xml
<project>
    <repositories>
        <repository>
            <id>maven-central</id>
            <url>https://repo.maven.apache.org/maven2</url>
        </repository>
        <repository>
            <id>jitpack.io</id>
            <url>https://jitpack.io</url>
        </repository>
    </repositories>
    
    <dependencies>
        <dependency>
            <groupId>com.github.KimHJ97</groupId>
            <artifactId>simple-jwt</artifactId>
            <version>1.0.5</version>
        </dependency>
    </dependencies>
</project>
```

 - Gradle
```groovy
repositories {
    mavenCentral()
    maven { url 'https://jitpack.io' }
}

dependencies {
    implementation 'com.github.KimHJ97:simple-jwt:1.0.4'
}
```

## How to Use

```java
// 1. Create HS256 Secret Key
SecretKey secretKey = JWT.generateSecretKey(Algorithm.HS256);
String secretKeyBase64 = Base64.getEncoder().encodeToString(secretKey.getEncoded());

// 2. Create Json Web Token
String jwt = JWT.builder()
        .algorithm(Algorithm.ES256)
        .secretKey(secretKey)
        .issuer("HongGilDong")
        .subject("user-token")
        .claim("age", 20)
        .claim("isAdmin", true)
        .issuedAt(ZonedDateTime.of(LocalDateTime.of(2099, 12, 31, 23, 59), ZoneId.of("Asia/Seoul")))
        .expiraton(ZonedDateTime.of(LocalDateTime.of(2099, 12, 31, 23, 59), ZoneId.of("Asia/Seoul")))
        .build();

// 3. Extract Json Web Token
Payload payload = JWT.parser().signedKey(HMAC256_SECRET_KEY)
	.payload(token);

String issuer = payload.getIssuer();
String subject = payload.getSubject();
int age = payload.getClaim("age", Integer.class);
boolean isAdmin = payload.getClaim("isAdmin", Boolean.class);
```

### Exception Handling

__JwtException__ is a custom exception that includes an error code from the __JwtErrorCode__ enum, which helps identify specific JWT-related issues. This allows for precise error handling and improved debugging.

```java
try {
    String jwt = JWT.builder()
        .algorithm(Algorithm.ES256)
        .secretKey(privateKey)
        .issuer("HongGilDong")
        .issuedAt(ZonedDateTime.of(LocalDateTime.of(2099, 12, 31, 23, 59), ZoneId.of("Asia/Seoul")))
        .expiraton(ZonedDateTime.of(LocalDateTime.of(2099, 12, 31, 23, 59), ZoneId.of("Asia/Seoul")))
        .build();
    
    Payload payload = JWT.parser()
        .signedKey(secretKey)
        .payload(jwt);
} catch (JwtException e) {
    JwtErrorCode errorCode = e.getErrorCode();
    switch (errorCode) {
        case INVALID_CLAIMS -> throw new IllegalArgumentException("The token is invalid.");
        case INVALID_SIGNATURE -> throw new IllegalArgumentException("The signature is invalid.");
        default -> throw new RuntimeException("An unknown error occurred.");
    }
}
```

## Planned Updates

- **RS256 Algorithm Support**: Implementation of the RS256 (RSA Signature with SHA-256) algorithm for enhanced security and compatibility with various systems.
- **RS384 Algorithm Support**: Implementation of the RS384 (RSA Signature with SHA-384) algorithm for enhanced security and compatibility with various systems.
- **RS512 Algorithm Support**: Implementation of the RS512 (RSA Signature with SHA-RS512) algorithm for enhanced security and compatibility with various systems.
- **ES256 Algorithm Support**: Addition of the ES256 (ECDSA using P-256 and SHA-256) algorithm to provide stronger security with elliptic curve cryptography.
- **ES384 Algorithm Support**: Addition of the ES384 (ECDSA using P-384 and SHA-384) algorithm to provide stronger security with elliptic curve cryptography.
- **ES512 Algorithm Support**: Addition of the ES512 (ECDSA using P-512 and SHA-512) algorithm to provide stronger security with elliptic curve cryptography.
- **PS256 Algorithm Support**: Introduction of the PS256 (RSASSA-PSS using SHA-256 and MGF1 with SHA-256) algorithm for improved security through probabilistic signature scheme.
- **PS384 Algorithm Support**: Introduction of the PS384 (RSASSA-PSS using SHA-384 and MGF1 with SHA-384) algorithm for improved security through probabilistic signature scheme.
- **PS512 Algorithm Support**: Introduction of the PS512 (RSASSA-PSS using SHA-512 and MGF1 with SHA-512) algorithm for improved security through probabilistic signature scheme.
