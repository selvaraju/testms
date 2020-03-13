package pl.piomin.microservices.auth.config;

import com.sun.istack.internal.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;

/** JWT (JWS) authentication properties. */
@Configuration
@ConfigurationProperties(prefix = "auth")
public  class Auth {

    @NotNull
    /** HMAC using SHA-512 */
    private char[] signingKey;
    @NotNull private String header = HttpHeaders.AUTHORIZATION;
    @NotNull private String issuer = "AR-Auth";
    @NotNull private String tokenType = "Bearer";
    /** Enable JWT body compression. */
    private boolean compressionEnabled;
    /** Token expiry in secs. */
    private int expiresInSec;
    public char[] getSigningKey() {
        return signingKey;
    }
    public void setSigningKey(char[] signingKey) {
        this.signingKey = signingKey;
    }
    public String getHeader() {
        return header;
    }
    public void setHeader(String header) {
        this.header = header;
    }
    public int getExpiresInSec() {
        return expiresInSec;
    }
    public void setExpiresInSec(int expiresInSec) {
        this.expiresInSec = expiresInSec;
    }
    public String getIssuer() {
        return issuer;
    }
    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }
    public String getTokenType() {
        return tokenType;
    }
    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }
    public boolean isCompressionEnabled() {
        return compressionEnabled;
    }
    public void setCompressionEnabled(boolean compressionEnabled) {
        this.compressionEnabled = compressionEnabled;
    }
    @Override
    public String toString() {
        return "Auth{"
                + "header='"
                + header
                + '\''
                + ", issuer='"
                + issuer
                + '\''
                + ", tokenType='"
                + tokenType
                + '\''
                + ", compressionEnabled="
                + compressionEnabled
                + ", expiresInSec="
                + expiresInSec
                + '}';
    }
}