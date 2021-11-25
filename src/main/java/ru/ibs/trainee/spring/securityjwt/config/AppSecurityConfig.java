package ru.ibs.trainee.spring.securityjwt.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import ru.ibs.trainee.spring.securityjwt.auth.ApplicationUserService;
import ru.ibs.trainee.spring.securityjwt.jwt.JwtProvider;
import ru.ibs.trainee.spring.securityjwt.jwt.JwtTokenVerifierFilter;
import ru.ibs.trainee.spring.securityjwt.jwt.JwtUsernameAndPasswordAuthenticationFilter;

import static ru.ibs.trainee.spring.securityjwt.config.ApplicationUserRole.MANAGER;


@EnableGlobalMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
@EnableWebSecurity
@Configuration
public class AppSecurityConfig extends WebSecurityConfigurerAdapter { //Конфигурация безопасности приложения

    private final PasswordEncoder passwordEncoder;
    private final ApplicationUserService applicationUserService;
    private final JwtProvider jwtProvider;

    @Override
    protected void configure(HttpSecurity http) throws Exception { //метод конфигурации
        http
                .csrf().disable() // отключили фичу, которая защищает от подделки межсайтовых запросов, отключаются куки
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) //Spring Security никогда не создаст HttpSession и никогда не будет использовать его для получения SecurityContext
                .and()
                .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(), jwtProvider)) // добавляем свой фильтр (JwtUsernameAndPasswordAuthenticationFilter)
                .addFilterAfter(new JwtTokenVerifierFilter(jwtProvider), JwtUsernameAndPasswordAuthenticationFilter.class) // добавляем ещё один фильтр(JwtTokenVerifierFilter)
                .authorizeRequests() // позволяет ограничить доступ к эндпоинтам
                .antMatchers("/", "index").permitAll() // разрешаем доступ к главной странице
//                .antMatchers("manager/api/**").hasRole(MANAGER.name()) // только юзер с ролью менеджер может заходить по указанному адресу
//                .antMatchers(HttpMethod.DELETE, "/api/task/**").hasAuthority(TASK_WRITE.getPermission())
//                .antMatchers(HttpMethod.POST, "/api/task/**").hasAuthority(TASK_WRITE.getPermission())
//                .antMatchers(HttpMethod.PUT, "/api/task/**").hasAuthority(TASK_WRITE.getPermission())
//                .antMatchers("/api/task/**").hasAnyRole(EMPLOYEE.name(), TRAINEE.name())
                .anyRequest() //ограничит доступ для любой другой конечной точки , отличной от PUBLIC_URL
                .authenticated(); // пользователь должен быть аутентифицирован.
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() { // проверка подлинности юзера и пароля
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserService);
        return provider;
    }
}
