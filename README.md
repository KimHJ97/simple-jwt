# simple-jwt

## Features

 - Generate JSON Web Token
   - Algorithm Supported: HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512, PS256, PS384, PS512 
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
            <version>1.0.6</version>
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
    implementation 'com.github.KimHJ97:simple-jwt:1.0.6'
}
```

## How to Use

 - HS256 Algorithm Usage
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
 - ES256 Algorithm Usage
```java
// 1. Create KeyPair(PrivateKey, PublicKey)
KeyPair keyPair = JWT.generateKeyPair(JWT.Algorithm.ES256, JWT.KeySize.LOW);
PrivateKey privateKey = keyPair.getPrivate();
PublicKey publicKey = keyPair.getPublic();

// 2. Create Json Web Token
String jwt = JWT.builder()
	.algorithm(Algorithm.ES256)
	.privateKey(privateKey)
	.issuer("HongGilDong")
	.subject("user-token")
	.claim("age", 20)
	.claim("isAdmin", true)
	.issuedAt(ZonedDateTime.of(LocalDateTime.of(2099, 12, 31, 23, 59), ZoneId.of("Asia/Seoul")))
	.expiraton(ZonedDateTime.of(LocalDateTime.of(2099, 12, 31, 23, 59), ZoneId.of("Asia/Seoul")))
	.build();

// 3. Extract Json Web Token
Payload payload = JWT.parser().publicKey(publicKey)
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

 - To Be Determined