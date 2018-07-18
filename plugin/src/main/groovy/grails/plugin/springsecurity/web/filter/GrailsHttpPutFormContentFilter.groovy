package grails.plugin.springsecurity.web.filter

import groovy.transform.CompileStatic
import groovy.util.logging.Slf4j
import org.grails.web.filters.HiddenHttpMethodFilter
import org.grails.web.servlet.mvc.GrailsWebRequest
import org.grails.web.util.WebUtils
import org.springframework.http.MediaType
import org.springframework.util.Assert
import org.springframework.util.LinkedMultiValueMap
import org.springframework.util.MultiValueMap
import org.springframework.util.StringUtils
import org.springframework.web.filter.HttpPutFormContentFilter

import javax.servlet.FilterChain
import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletRequestWrapper
import javax.servlet.http.HttpServletResponse

@Slf4j
@CompileStatic
class GrailsHttpPutFormContentFilter extends HttpPutFormContentFilter {

    HttpMethodOverrideDetector httpMethodOverrideDetector = new HttpMethodOverrideDetector()

    /**
     * Set the parameter name to look for HTTP methods.
     */
    void setMethodParam(String methodParam) {
        httpMethodOverrideDetector.setMethodParam(methodParam)
    }

    @Override
    protected void doFilterInternal(final HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String httpMethodOverride = httpMethodOverrideDetector.getHttpMethodOverride(request)
        if ((request.getMethod().toUpperCase() in ['PUT', 'PATCH']) &&
                isFormContentType(request) &&
                (!StringUtils.hasLength(httpMethodOverride) || !['PUT', 'PATCH'].contains(httpMethodOverride?.toUpperCase()))
        ) {
            GrailsWebRequest grailsWebRequest = WebUtils.retrieveGrailsWebRequest()
            Map grailsParameterMap = grailsWebRequest.parameterMap

            MultiValueMap<String, String> formParameters = new LinkedMultiValueMap(grailsParameterMap?.size() ?: 0)
            grailsParameterMap.each { k, v ->
                formParameters.add((String) k, (String) v)
            }

            HttpServletRequest wrapper = new HttpPutFormContentRequestWrapper(request, formParameters)
            filterChain.doFilter(wrapper, response)
        } else {
            filterChain.doFilter(request, response)
        }
    }

    private boolean isFormContentType(HttpServletRequest request) {
        String contentType = request.contentType
        if (contentType == null) {
            return false
        }
        MediaType mediaType
        try {
            mediaType = MediaType.parseMediaType(contentType)
        } catch (IllegalArgumentException ex) {
            return false
        }
        return (MediaType.APPLICATION_FORM_URLENCODED.includes(mediaType))
    }

    private static class HttpPutFormContentRequestWrapper extends HttpServletRequestWrapper {

        private MultiValueMap<String, String> formParameters

        public HttpPutFormContentRequestWrapper(HttpServletRequest request, MultiValueMap<String, String> parameters) {
            super(request)
            this.formParameters = (parameters != null ? parameters : new LinkedMultiValueMap<String, String>())
        }

        @Override
        public String getParameter(String name) {
            String queryStringValue = super.getParameter(name)
            String formValue = this.formParameters.getFirst(name)
            return (queryStringValue != null ? queryStringValue : formValue)
        }

        @Override
        public Map<String, String[]> getParameterMap() {
            Map<String, String[]> result = new LinkedHashMap<String, String[]>()
            Enumeration<String> names = getParameterNames()
            while (names.hasMoreElements()) {
                String name = names.nextElement()
                result.put(name, getParameterValues(name))
            }
            return result
        }

        @Override
        public Enumeration<String> getParameterNames() {
            Set<String> names = new LinkedHashSet<String>()
            names.addAll(Collections.list(super.getParameterNames()))
            names.addAll(this.formParameters.keySet())
            return Collections.enumeration(names)
        }

        @Override
        public String[] getParameterValues(String name) {
            String[] queryStringValues = super.getParameterValues(name)
            List<String> formValues = this.formParameters.get(name)
            if (formValues == null) {
                return queryStringValues
            } else if (queryStringValues == null) {
                return formValues.toArray(new String[formValues.size()])
            } else {
                List<String> result = new ArrayList<String>(queryStringValues.length + formValues.size())
                result.addAll(Arrays.asList(queryStringValues))
                result.addAll(formValues)
                return result.toArray(new String[result.size()])
            }
        }
    }
}
