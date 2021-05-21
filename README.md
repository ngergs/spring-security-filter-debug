## Spring security filter debug project

### Keycloak workaround
Just to test how to fix keycloak regarding the spring security issue 9787.
The KeycloakConfig holds the configuration from the original KeycloakWebSecurityConfigureAdapter adjusted for the aforementioned issue.
The critical lines are:
```java
    @Override
protected void configure(HttpSecurity http) throws Exception{
        http.authorizeRequests();
        // taken from KeycloakWebSecurityConfigurerAdapter and worker around to avoid spring security issue 9787
        http
        .csrf().requireCsrfProtectionMatcher(keycloakCsrfRequestMatcher())
        .and()
        .sessionManagement()
        .sessionAuthenticationStrategy(sessionAuthenticationStrategy())
        .and()
        .addFilterBefore(keycloakPreAuthActionsFilter(),LogoutFilter.class)
        .addFilterBefore(keycloakAuthenticationProcessingFilter(),LogoutFilter.class)
        .addFilterAfter(keycloakSecurityContextRequestFilter(),SecurityContextHolderAwareRequestFilter.class)
        .addFilterAfter(keycloakAuthenticatedActionsRequestFilter(),SecurityContextHolderAwareRequestFilter.class)
        .exceptionHandling().authenticationEntryPoint(authenticationEntryPoint())
        .and()
        .logout()
        .addLogoutHandler(keycloakLogoutHandler())
        .logoutUrl("/sso/logout").permitAll()
        .logoutSuccessUrl("/");
}
```
Only the following line had to be adjusted:
```java
        .addFilterAfter(keycloakAuthenticatedActionsRequestFilter(),SecurityContextHolderAwareRequestFilter.class)
```