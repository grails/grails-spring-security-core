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

import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.web.FilterInvocation;

/**
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
public class InterceptUrlMapFilterInvocationDefinition extends AbstractFilterInvocationDefinition {

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

		reset();
	}

	@Override
	protected boolean stopAtFirstMatch() {
		return true;
	}

	@SuppressWarnings("unchecked")
	@Override
	public void reset() {
		Object map = ReflectionUtils.getConfigProperty("interceptUrlMap");
		if (!(map instanceof Map)) {
			_log.warn("interceptUrlMap config property isn't a Map");
			return;
		}

		resetConfigs();

		Map<String, List<String>> data = ReflectionUtils.splitMap((Map<String, Object>)map);
		for (Map.Entry<String, List<String>> entry : data.entrySet()) {
			compileAndStoreMapping(entry.getKey(), entry.getValue());
		}

		_initialized = true;
	}
}
