package com.testapp

import groovy.util.logging.Slf4j
import org.springframework.web.filter.GenericFilterBean

import javax.servlet.FilterChain
import javax.servlet.ServletException
import javax.servlet.ServletRequest
import javax.servlet.ServletResponse
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

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