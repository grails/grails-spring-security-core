/* Copyright 2006-2012 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.codehaus.groovy.grails.plugins.springsecurity;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.web.FilterInvocation;

/**
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
public class RequestmapFilterInvocationDefinition extends AbstractFilterInvocationDefinition {

	private boolean _initialized;

	@Override
	protected String determineUrl(final FilterInvocation filterInvocation) {
		HttpServletRequest request = filterInvocation.getHttpRequest();
		String requestUrl = request.getRequestURI().substring(request.getContextPath().length());
		return lowercaseAndStripQuerystring(requestUrl);
	}

	@Override
	protected void initialize() {
		if (_initialized) {
			return;
		}

		try {
			reset();
			_initialized = true;
		}
		catch (RuntimeException e) {
			_log.warn("Exception initializing; this is ok if it's at startup and due " +
					"to GORM not being initialized yet since the first web request will " +
					"re-initialize. Error message is: " + e.getMessage());
		}
	}

	/**
	 * Call at startup or when <code>Requestmap</code> instances have been added, removed, or changed.
	 */
	@Override
	public synchronized void reset() {
		Map<String, String> data = loadRequestmaps();
		resetConfigs();

		for (Map.Entry<String, String> entry : data.entrySet()) {
			compileAndStoreMapping(entry.getKey(), split(entry.getValue()));
		}

		if (_log.isTraceEnabled()) _log.trace("configs: " + getConfigAttributeMap());
	}

	protected Map<String, String> loadRequestmaps() {
		Map<String, String> data = new HashMap<String, String>();

		for (Object requestmap : ReflectionUtils.loadAllRequestmaps()) {
			String urlPattern = ReflectionUtils.getRequestmapUrl(requestmap);
			String configAttribute = ReflectionUtils.getRequestmapConfigAttribute(requestmap);
			data.put(urlPattern, configAttribute);
		}

		return data;
	}
}
