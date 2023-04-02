package com.srjons.templatejpa.controller;

import com.srjons.templatejpa.dtos.AuthRequest;
import com.srjons.templatejpa.dtos.AuthResponse;
import com.srjons.templatejpa.security.AuthUserDetailsService;
import com.srjons.templatejpa.utils.JWTUtility;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/authenticate")
public class AuthenticateController {

    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private JWTUtility jwtUtility;
    @Autowired
    private AuthUserDetailsService userService;

    @PostMapping
    public AuthResponse authenticate(@RequestBody AuthRequest authRequest) throws Exception {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            authRequest.getUsername(),
                            authRequest.getPassword()
                    )
            );
        } catch (BadCredentialsException e) {
            throw new Exception("INVALID_CREDENTIALS", e);
        }

        final UserDetails userDetails
                = userService.loadUserByUsername(authRequest.getUsername());

        final String token =
                jwtUtility.generateToken(userDetails);

        return new AuthResponse(token);
    }
}
