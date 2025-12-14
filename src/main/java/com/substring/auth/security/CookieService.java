package com.substring.auth.security;

import jakarta.servlet.http.HttpServletResponse;
import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;

@Service
@Getter
public class CookieService {

    private final String refreshTokenCookieName;

    private final boolean cookieHttpOnly;

    private final boolean cookieSecure;

    private final String coookieDomain;

    private final String cookieSameSite;

    private final Logger logger= LoggerFactory.getLogger(CookieService.class);

    public CookieService(@Value("${security.jwt.refresh-token-cookie-name}") String refreshTokenCookieName,
                         @Value("${security.jwt.cookie-http-only}") boolean cookieHttpOnly,
                         @Value("${security.jwt.cookie-secure}") boolean cookieSecure,
                         @Value("${security.jwt.cookie-domain}") String coookieDomain,
                         @Value("${security.jwt.cookie-same-site}") String cookieSameSite) {
        this.refreshTokenCookieName = refreshTokenCookieName;
        this.cookieHttpOnly = cookieHttpOnly;
        this.cookieSecure = cookieSecure;
        this.coookieDomain = coookieDomain;
        this.cookieSameSite = cookieSameSite;
    }

    //create method to attach cookie to response
    public void attachRefreshCookie(HttpServletResponse response,String value,int maxAge){
        logger.info("Attaching cookie with name : {} and value : {}",refreshTokenCookieName,value);
        var responseCookieBuilder=ResponseCookie.from(refreshTokenCookieName,value)
                .httpOnly(cookieHttpOnly)
                .secure(cookieSecure)
                .path("/")
                .maxAge(maxAge)
                .sameSite(cookieSameSite);

        if(coookieDomain!=null && !coookieDomain.isBlank()){
            responseCookieBuilder.domain(coookieDomain);
        }

        ResponseCookie responseCookie=responseCookieBuilder.build();

        response.addHeader(HttpHeaders.SET_COOKIE,responseCookie.toString());
    }

    //clear the refresh cookie

    public void clearRefreshCookie(HttpServletResponse response){
        ResponseCookie.ResponseCookieBuilder builder=ResponseCookie.from(refreshTokenCookieName,"")
                .maxAge(0)
                .httpOnly(cookieHttpOnly)
                .path("/")
                .sameSite(cookieSameSite)
                .secure(cookieSecure);

        if (coookieDomain!=null && !coookieDomain.isBlank()){
            builder.domain(coookieDomain);
        }

        ResponseCookie responseCookie=builder.build();
        response.addHeader(HttpHeaders.SET_COOKIE,responseCookie.toString());
    }

    public void addNoStoreHeaders(HttpServletResponse response){
        response.setHeader(HttpHeaders.CACHE_CONTROL,"no-store");
        response.setHeader("Pragma","no-cache");
    }


}
