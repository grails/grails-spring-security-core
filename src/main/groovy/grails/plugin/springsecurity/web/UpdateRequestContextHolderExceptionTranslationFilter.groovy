package grails.plugin.springsecurity.web

import grails.async.web.AsyncGrailsWebRequest
import groovy.transform.CompileStatic
import org.grails.web.servlet.mvc.GrailsWebRequest
import org.grails.web.util.WebUtils
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.security.web.access.ExceptionTranslationFilter
import org.springframework.security.web.savedrequest.RequestCache
import org.springframework.web.context.request.RequestContextHolder

import javax.servlet.FilterChain
import javax.servlet.ServletException
import javax.servlet.ServletRequest
import javax.servlet.ServletResponse
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 * Replaces the current GrailsWebRequest with one that delegates to the real current instance but uses the request and
 * response from the filter chain instead of the cached instances from earlier in the chain to ensure that controllers
 * and other classes that access the request from the thread-local RequestContextHolder use the correct instances.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
@CompileStatic
class UpdateRequestContextHolderExceptionTranslationFilter extends ExceptionTranslationFilter {

	UpdateRequestContextHolderExceptionTranslationFilter(AuthenticationEntryPoint authenticationEntryPoint) {
		super(authenticationEntryPoint)
	}

	UpdateRequestContextHolderExceptionTranslationFilter(AuthenticationEntryPoint authenticationEntryPoint, RequestCache requestCache) {
		super(authenticationEntryPoint, requestCache)
	}

	void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;
		GrailsWebRequest current = (GrailsWebRequest)RequestContextHolder.requestAttributes
		if (current && !(current instanceof DelegatingGrailsWebRequest) && !(current instanceof DelegatingAsyncGrailsWebRequest)) {
			if (current instanceof AsyncGrailsWebRequest) {
				WebUtils.storeGrailsWebRequest new DelegatingAsyncGrailsWebRequest(request, response, current)
			}
			else {
				WebUtils.storeGrailsWebRequest new DelegatingGrailsWebRequest(request, response, current)
			}
		}

		super.doFilter request, response, chain
	}
}

@CompileStatic
class DelegatingGrailsWebRequest extends GrailsWebRequest {

	@Delegate
	GrailsWebRequest current

	DelegatingGrailsWebRequest(HttpServletRequest request, HttpServletResponse response, GrailsWebRequest current) {
		super(request, response, current.attributes)
	}
}

@CompileStatic
class DelegatingAsyncGrailsWebRequest extends AsyncGrailsWebRequest {

	@Delegate
	AsyncGrailsWebRequest current

	DelegatingAsyncGrailsWebRequest(HttpServletRequest request, HttpServletResponse response, AsyncGrailsWebRequest current) {
		super(request, response, current.attributes)
	}
}
