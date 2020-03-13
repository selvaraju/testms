package pl.piomin.microservices.auth.token;
import static org.springframework.util.StringUtils.isEmpty;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.CompressionCodecs;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import pl.piomin.microservices.auth.config.Auth;
import pl.piomin.microservices.auth.user.ARUser;
import zipkin.internal.Nullable;

import javax.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;
@Service
public class JwtTokenService {
    private static final Logger log = LoggerFactory.getLogger(JwtTokenService.class);
    private static final String ROLE_CLAIM = "roles";
    private static final String LICENSE_CLAIM = "license";
    private static SignatureAlgorithm SIGNATURE_ALGORITHM = SignatureAlgorithm.HS512;
    private final char[] secretKey;
    private final int expiresInSec;
    private final String issuer;
    private final String tokenHeader;
    private final String tokenType;
    private final boolean compressionEnabled;
    public JwtTokenService(Auth authConfig) {
        secretKey = authConfig.getSigningKey();
        expiresInSec = authConfig.getExpiresInSec();
        issuer = authConfig.getIssuer();
        tokenHeader = authConfig.getHeader();
        tokenType = authConfig.getTokenType();
        compressionEnabled = authConfig.isCompressionEnabled();
    }
    /**
     * Generate a JWT token for the given user. The roles will be stored as a claim in JWT token as a
     * comma separated string.
     *
     * @param user authenticated user details object.
     * @return compact JWS (JSON Web Signature)
     */
    public String generateToken(ARUser user) {
        Instant now = Instant.now();
        Instant expiresIn = now.plusSeconds(expiresInSec);
        JwtBuilder jwt =
                Jwts.builder()
                        .setSubject(user.getUsername())
                        .setIssuer(issuer)
                        .setIssuedAt(Date.from(now))
                        .setExpiration(Date.from(expiresIn))
                        .signWith(SIGNATURE_ALGORITHM, String.valueOf(secretKey));
        if (user.getAuthorities() != null) {
            List<String> roles =
                    user.getAuthorities()
                            .stream()
                            .map(GrantedAuthority::getAuthority)
                            .collect(Collectors.toList());
            jwt.claim(ROLE_CLAIM, String.join(",", roles));
        }
        if (user.getLicense() != null) {
            jwt.claim(LICENSE_CLAIM, user.getLicense());
        }

        if (compressionEnabled) {
            jwt.compressWith(CompressionCodecs.DEFLATE);
        }
        return jwt.compact();
    }
    /**
     * Validates token and creates the user details object by extracting identity and authorization
     * claims. It throws a Runtime exception if the token is invalid or expired.
     *
     * @param token jwt token
     * @return {@link ARUser}
     */
    public ARUser createUser(String token) {
        Claims claims =
                Jwts.parser().setSigningKey(String.valueOf(secretKey)).parseClaimsJws(token).getBody();
        String username = claims.getSubject();
        List<GrantedAuthority> authorities = getAuthorities(claims);


        String license = claims.getOrDefault(LICENSE_CLAIM, username).toString();
        return new ARUser(username, "", authorities, license);
    }
    /**
     * Validates and returns the claims of given JWS
     *
     * @param token compact JWS (JSON Web Signature)
     * @return {@link Claims} . Returns <code>null</code> if it fails to verify/expires the JWT.
     */
    public @Nullable Claims getClaims( String token) {
        Claims claims;
        try {
            claims =
                    Jwts.parser().setSigningKey(String.valueOf(secretKey)).parseClaimsJws(token).getBody();
        } catch (JwtException e) {
            log.debug("JWT token parser error.", e);
            claims = null;
        }
        return claims;
    }
    /**
     * A helper method to returns authority from the role claim. The role is a string of comma
     * separated values.
     *
     * @param claims JWT claims.
     * @return list of {@link SimpleGrantedAuthority}
     */
    private  List<GrantedAuthority> getAuthorities(Claims claims) {
        String rolesStr = claims.getOrDefault(ROLE_CLAIM, "").toString();
        return Arrays.stream(rolesStr.split(","))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }
    /**
     * Returns the list of roles from {@link Authentication}
     *
     * @param auth authentication object
     * @return list of strings.
     */
    private @Nullable List<String> getRoles( Authentication auth) {
        Collection<? extends GrantedAuthority> authorities = auth.getAuthorities();
        if (authorities != null) {
            return authorities.stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList());
        }
        return null;
    }
    /**
     * Retrieves the JWT authentication token from http request.
     *
     * @param req http request.
     * @return {@link JwtAuthToken} or <code>null</code> if the Bearer token is not present or empty.
     */
    public @Nullable JwtAuthToken getAccessToken( HttpServletRequest req) {
        log.debug("Getting the access token for " + req.getRequestURI());
        String bearerToken = req.getHeader(tokenHeader);
        if (bearerToken != null) {
            // Make sure it's valid token type.
            if (!bearerToken.startsWith(tokenType)) {
                throw new AuthenticationCredentialsNotFoundException("Invalid Authorization Token.");
            }
            String jwtToken = bearerToken.replaceFirst(tokenType, "").trim();
            if (!isEmpty(jwtToken)) {
                return new JwtAuthToken("JwtToken", jwtToken, Collections.emptyList());
            }
        }
        log.debug("JWT Bearer token is null/empty for " + req.getRequestURI());
        return null;
    }
    public int getExpiresInSec() {
        return expiresInSec;
    }
    public String getIssuer() {
        return issuer;
    }
    public String getTokenHeader() {
        return tokenHeader;
    }
    public String getTokenType() {
        return tokenType;
    }
}