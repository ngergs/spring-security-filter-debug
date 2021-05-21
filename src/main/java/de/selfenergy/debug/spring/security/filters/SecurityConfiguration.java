package de.selfenergy.debug.spring.security.filters;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    static public class SpringRelativeFilter extends OncePerRequestFilter{
        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
            filterChain.doFilter(request,response);
        }
    }
    static public class CustomRelativeFilter extends OncePerRequestFilter{
        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
            filterChain.doFilter(request,response);
        }
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // test case add class SpringRelativeFilter works, but adding the CustomRelativeFilter class fails
        http.addFilterAfter(new SpringRelativeFilter(), SecurityContextHolderAwareRequestFilter.class)
            .addFilterAfter(new CustomRelativeFilter(), SpringRelativeFilter.class);
    }

}
