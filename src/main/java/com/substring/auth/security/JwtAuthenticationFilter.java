package com.substring.auth.security;

import com.substring.auth.entities.Role;
import com.substring.auth.entities.User;
import com.substring.auth.helpers.UserHelper;
import com.substring.auth.repositories.UserRepository;
import io.jsonwebtoken.*;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;

    private final UserRepository userRepository;

    private Logger logger= LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    //this filter will run before request

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String header=request.getHeader("Authorization");

        logger.info("Authorization header :{} ",header);

        if (header!=null && header.startsWith("Bearer ")){

            //token extract and validate then authentication create and thrn security context setting

            String token=header.substring(7);



            try{

                if (!jwtService.isAccessToken(token)){
                    //message pass
                    filterChain.doFilter(request,response);
                    return;
                }

                Jws<Claims>parse =jwtService.parse(token);



                Claims payload=parse.getPayload();



                String userId=payload.getSubject();

                UUID userUuid= UserHelper.parseUUID(userId);

                userRepository.findById(userUuid)
                        .ifPresent(user->{

                            //check for user enable or not
                            if (user.isEnabled()){
                                List<GrantedAuthority>authorities=user.getRoles()==null?List.of():user.getRoles().stream()
                                        .map(role->new SimpleGrantedAuthority(role.getName())).collect(Collectors.toList());

                                //work as authentication
                                UsernamePasswordAuthenticationToken authentication=new UsernamePasswordAuthenticationToken(
                                        user.getEmail(),
                                        null,
                                        authorities
                                );

                                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                                //final line to set the authentication to security password
                                if (SecurityContextHolder.getContext().getAuthentication()==null)
                                    SecurityContextHolder.getContext().setAuthentication(authentication);

                            }

                           });

            } catch (ExpiredJwtException e) {
                request.setAttribute("error","Token Expired");
//                e.printStackTrace();
            }catch (Exception e){
                request.setAttribute("error","Invalid Token");
//                e.printStackTrace();
            }
        }

        filterChain.doFilter(request,response);
        //
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException{
        return request.getRequestURI().startsWith("/api/v1/auth/");
    }
}
