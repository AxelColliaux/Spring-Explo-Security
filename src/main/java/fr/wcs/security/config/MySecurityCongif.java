package fr.wcs.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class MySecurityCongif {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((authz) -> {
            try {
                authz
                    .requestMatchers("/").permitAll()
                    .requestMatchers("/avengers/assemble").hasAnyRole("CHAMPION", "DIRECTOR")
                    .requestMatchers("/secret-bases").hasRole("DIRECTOR")
                    .anyRequest().authenticated()
                    .and().formLogin()
                    .and().httpBasic();
                    
            } catch (Exception e) {

                e.printStackTrace();
            }
        });
        return http.build();
    }

    @Bean
    public InMemoryUserDetailsManager userDetailsService() {
        PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();

        UserDetails user = User
			.withUsername("user")
			.password(encoder.encode("password"))
			.roles("")
			.build();

        UserDetails champion = User
            .withUsername("Steve")
            .password(encoder.encode("motdepasse"))
            .roles("CHAMPION")
            .build();

        UserDetails director = User
            .withUsername("Nick")
            .password(encoder.encode("flerken"))
            .roles("DIRECTOR")
            .build();

        return new InMemoryUserDetailsManager(user, champion, director);
    }
}
