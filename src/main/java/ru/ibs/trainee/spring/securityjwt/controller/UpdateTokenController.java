package ru.ibs.trainee.spring.securityjwt.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ru.ibs.trainee.spring.securityjwt.jwt.JwtProvider;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequiredArgsConstructor
@RequestMapping("api/update")
public class UpdateTokenController {

    private final JwtProvider jwtProvider;

    @RequestMapping("token")
    public void updateToken(HttpServletRequest req, HttpServletResponse res, Authentication authentication) throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();
        Map<String, String> tokens = new HashMap<>();
        String token = jwtProvider.createToken(authentication);
        String refreshToken = jwtProvider.createRefreshToken(authentication);
        tokens.put("access token", token);
        tokens.put("refresh_token",refreshToken);
        res.setContentType(MediaType.APPLICATION_JSON_VALUE);
        objectMapper.writeValue(res.getOutputStream(), tokens);

    }
}
