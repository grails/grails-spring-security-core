/* Copyright 2006-2014 SpringSource.
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

import java.util.List;
import java.util.Map;

/**
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
public class InterceptUrlMapFilterInvocationDefinition extends AbstractFilterInvocationDefinition {

	@Override
	protected void initialize() {
		if (!initialized) {
			reset();
		}
	}

	@Override
	protected boolean stopAtFirstMatch() {
		return true;
	}

	@SuppressWarnings("unchecked")
	@Override
	public void reset() {
		Object map = ReflectionUtils.getConfigProperty("interceptUrlMap");
		if (!(map instanceof Map || map instanceof List)) {
			log.warn("interceptUrlMap config property isn't a Map or a List of Maps");
			return;
		}

		resetConfigs();

		List<InterceptedUrl> data = map instanceof Map ? ReflectionUtils.splitMap((Map<String, Object>)map) :
		                                                 ReflectionUtils.splitMap((List<Map<String, Object>>)map);
		for (InterceptedUrl iu : data) {
			compileAndStoreMapping(iu);
		}

		initialized = true;
	}
}
