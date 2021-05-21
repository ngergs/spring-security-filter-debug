## Spring security filter debug project

This is a simple project to reproduce a behaviour thas has been introduced with spring security 5.5.0 and has been included
in spring boot 2.5.0. Adding a filter relative (before/after) to a custom, i.e. non-standard spring filter, results in an error.
```java
        http.addFilterAfter(new SpringRelativeFilter(), SecurityContextHolderAwareRequestFilter.class)
            .addFilterAfter(new CustomRelativeFilter(), SpringRelativeFilter.class);
```
The above logic works with spring boot 2.4.5 but breaks with spring boot 2.5.0.