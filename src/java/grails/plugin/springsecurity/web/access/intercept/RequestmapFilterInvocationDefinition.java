/* Copyright 2006-2013 SpringSource.
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
package grails.plugin.springsecurity.web.access.intercept;

import grails.plugin.springsecurity.InterceptedUrl;
import grails.plugin.springsecurity.ReflectionUtils;

import java.util.ArrayList;
import java.util.List;

import org.springframework.http.HttpMethod;

/**
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
public class RequestmapFilterInvocationDefinition extends AbstractFilterInvocationDefinition {

	@Override
	protected void initialize() {
		if (initialized) {
			return;
		}

		try {
			reset();
			initialized = true;
		}
		catch (RuntimeException e) {
			log.warn("Exception initializing; this is ok if it's at startup and due " +
					"to GORM not being initialized yet since the first web request will " +
					"re-initialize. Error message is: {0}", e.getMessage());
		}
	}

	/**
	 * Call at startup or when <code>Requestmap</code> instances have been added, removed, or changed.
	 */
	@Override
	public synchronized void reset() {
		resetConfigs();

		for (InterceptedUrl iu : loadRequestmaps()) {
			compileAndStoreMapping(iu);
		}

		if (log.isTraceEnabled()) {
			log.trace("configs: {0}", getConfigAttributeMap());
		}
	}

	protected List<InterceptedUrl> loadRequestmaps() {
		List<InterceptedUrl> data = new ArrayList<InterceptedUrl>();

		boolean supportsHttpMethod = ReflectionUtils.requestmapClassSupportsHttpMethod();

		for (Object requestmap : ReflectionUtils.loadAllRequestmaps()) {
			String urlPattern = ReflectionUtils.getRequestmapUrl(requestmap);
			String configAttribute = ReflectionUtils.getRequestmapConfigAttribute(requestmap);
			HttpMethod method = supportsHttpMethod ? ReflectionUtils.getRequestmapHttpMethod(requestmap) : null;
			data.add(new InterceptedUrl(urlPattern, split(configAttribute), method));
		}

		return data;
	}
}
