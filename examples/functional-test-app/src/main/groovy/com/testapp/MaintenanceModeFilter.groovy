package com.testapp

import groovy.util.logging.Slf4j
import org.springframework.web.filter.GenericFilterBean

import jakarta.servlet.FilterChain
import jakarta.servlet.ServletException
import jakarta.servlet.ServletRequest
import jakarta.servlet.ServletResponse
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse

/**
 * If registered, this filter results in an HttpStatus of 500 being returned to the client
 */
@Slf4j
class MaintenanceModeFilter extends GenericFilterBean {

    void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest)req
        HttpServletResponse response = (HttpServletResponse)res

        if(request.requestURI in ['/hack/blankPage', '/error']) {
            chain.doFilter request, response
        } else {
            throw new NullPointerException()
        }

    }
}