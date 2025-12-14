package com.substring.auth.controlllers;

import com.substring.auth.dtos.LoginRequest;
import com.substring.auth.dtos.RefreshTokenRequest;
import com.substring.auth.dtos.TokenResponse;
import com.substring.auth.dtos.UserDto;
import com.substring.auth.entities.RefreshToken;
import com.substring.auth.entities.User;
import com.substring.auth.repositories.RefreshTokenRepo;
import com.substring.auth.repositories.UserRepository;
import com.substring.auth.security.CookieService;
import com.substring.auth.security.JwtService;
import com.substring.auth.services.AuthService;
import io.jsonwebtoken.JwtException;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/auth")
@AllArgsConstructor
public class AuthController {

    private final RefreshTokenRepo refreshTokenRepo;

    private final AuthService authService;

    private final AuthenticationManager authenticationManager;

    private final UserRepository userRepository;

    private final JwtService jwtService;

    private final ModelMapper modelMapper;

    private final CookieService cookieService;


    //login method
    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(
            @RequestBody LoginRequest loginRequest,
            HttpServletResponse response
    ){
        //authenticate
        Authentication authentication=authenticate(loginRequest);
        User user=userRepository.findByEmail(loginRequest.email()).orElseThrow(()->new BadCredentialsException("Invalid Username and Password"));
        if (!user.isEnabled()){
            throw  new DisabledException("User is Disabled");
        }

        String jti= UUID.randomUUID().toString();
        var refreshTokenObj= RefreshToken.builder()
                .jti(jti)
                .user(user)
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(jwtService.getRefreshTtlSeconds()))
                .revoked(false)
                .build();

        //save refresh token
        refreshTokenRepo.save(refreshTokenObj);


        //access token ---> generate jwt token
        String accessToken= jwtService.generateAccessToken(user);
        String refreshToken=jwtService.generateRefreshToken(user,refreshTokenObj.getJti());

        //use cookie service to attach refresh token in cookie

        cookieService.attachRefreshCookie(response,refreshToken,(int)jwtService.getRefreshTtlSeconds());
        cookieService.addNoStoreHeaders(response);

        TokenResponse tokenResponse=TokenResponse.of(accessToken,refreshToken,jwtService.getAccessTtlSeconds(),modelMapper.map(user,UserDto.class));

        return ResponseEntity.ok(tokenResponse);

    }


    //Authenticate
    private Authentication authenticate(LoginRequest loginRequest) {

        try {
            //authentication
            return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.email(),loginRequest.password()));

        } catch (Exception e) {
            throw new BadCredentialsException("Username or password is not valid");
        }
    }

    //access and refresh token renew
    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refreshToken(
            @RequestBody(required = false) RefreshTokenRequest body,
            HttpServletResponse response,
            HttpServletRequest request
    ){

        String refreshToken=readRefreshTokenFromRequest(body,request).orElseThrow(()-> new BadCredentialsException("Invalid Refresh is Missing"));

        //check to refresh this token
        if (!jwtService.isRefreshToken(refreshToken)){
            throw new BadCredentialsException("Invalid refresh token type");
        }

        String jti=jwtService.getJti(refreshToken);

        UUID userId=jwtService.getUserId(refreshToken);

        //refreshtoken repository
        RefreshToken storedRefreshToken=refreshTokenRepo.findByJti(jti).orElseThrow(()->new BadCredentialsException("invalid refresh token"));

        if (storedRefreshToken.isRevoked()){
            throw new BadCredentialsException("Refresh token is revoked");
        }

        if (storedRefreshToken.getExpiresAt().isBefore(Instant.now())){
            throw new BadCredentialsException("Refresh token expired");
        }

        if (!storedRefreshToken.getUser().getId().equals(userId)){
            throw new BadCredentialsException("Token subject mismatched");
        }

        //refresh token ko rotate
        storedRefreshToken.setRevoked(true);

        String newJti=UUID.randomUUID().toString();
        storedRefreshToken.setReplacedByToken(newJti);

        refreshTokenRepo.save(storedRefreshToken);

        User user=storedRefreshToken.getUser();

        var newRefreshTokenOb=RefreshToken.builder()
                .jti(newJti)
                .user(user)
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(jwtService.getRefreshTtlSeconds()))
                .revoked(false)
                .build();

        refreshTokenRepo.save(newRefreshTokenOb);
        String newAccessToken=jwtService.generateAccessToken(user);
        String newRefreshToken=jwtService.generateRefreshToken(user,newRefreshTokenOb.getJti());

        cookieService.attachRefreshCookie(response,newRefreshToken,(int) jwtService.getRefreshTtlSeconds());
        cookieService.addNoStoreHeaders(response);

        return ResponseEntity.ok(TokenResponse.of(newAccessToken,newRefreshToken, jwtService.getAccessTtlSeconds(),modelMapper.map(user,UserDto.class)));

    }

    //

    private Optional<String> readRefreshTokenFromRequest(RefreshTokenRequest body, HttpServletRequest request) {
        // 1. prefer reading refresh token from cookie

        if (request.getCookies()!=null){
            Optional<String> fromCookie=Arrays.stream(request.getCookies())
                    .filter(c->cookieService.getRefreshTokenCookieName().equals(c.getName()))
                    .map(c->c.getValue())
                    .filter(v->!v.isBlank())
                    .findFirst();

            if (fromCookie.isPresent()) return fromCookie;
        }

        //1.body

        if (body!=null && body.refreshToken()!=null && !body.refreshToken().isBlank()){
            return Optional.of(body.refreshToken());
        }

        //3. custom header
        String refreshHeader=request.getHeader("X-Refresh-Token");
        if (refreshHeader!=null && !refreshHeader.isBlank()){
            return Optional.of(refreshHeader.trim());
        }

        //Authorization = Bearer <token>
        // Authorization = Bearer <token>
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (authHeader != null && authHeader.regionMatches(true, 0, "Bearer ", 0, 7)) {
            String candidate = authHeader.substring(7).trim();

            if (!candidate.isEmpty()) {
                try {
                    if (jwtService.isRefreshToken(candidate)) {
                        return Optional.of(candidate);
                    }
                } catch (Exception ignored) {
                    // intentionally ignored
                }
            }
        }

        return Optional.empty();

    }

    // logout
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request,HttpServletResponse response){
        readRefreshTokenFromRequest(null,request).ifPresent(token->{
           try{
               if (jwtService.isRefreshToken(token)){
                   String jti=jwtService.getJti(token);
                   refreshTokenRepo.findByJti(jti).ifPresent(rt->{
                       rt.setRevoked(true);
                       refreshTokenRepo.save(rt);
                   });
               }
           }catch (JwtException ignored){

           }
        });

        cookieService.clearRefreshCookie(response);
        cookieService.addNoStoreHeaders(response);
        SecurityContextHolder.clearContext();
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }


    @PostMapping("/register")
    public ResponseEntity<UserDto> registerUser(@RequestBody UserDto userDto){
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.registerUser(userDto));
    }

}
