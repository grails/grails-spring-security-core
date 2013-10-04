/* Copyright 2012-2013 SpringSource.
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
package grails.plugin.springsecurity.web.access.channel;

import java.io.IOException;
import java.util.Collection;

import javax.servlet.ServletException;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.channel.SecureChannelProcessor;
import org.springframework.util.Assert;

/**
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
public class HeaderCheckSecureChannelProcessor extends SecureChannelProcessor {

	protected String headerName;
	protected String headerValue;

	@Override
	public void decide(FilterInvocation invocation, Collection<ConfigAttribute> config)
			throws IOException, ServletException {

		Assert.isTrue(invocation != null && config != null, "Nulls cannot be provided");

		for (ConfigAttribute attribute : config) {
			if (supports(attribute)) {
				if (headerValue.equals(invocation.getHttpRequest().getHeader(headerName))) {
					getEntryPoint().commence(invocation.getRequest(), invocation.getResponse());
				}
			}
		}
	}

	/**
	 * Set the name of the header to check.
	 * @param name the name
	 */
	public void setHeaderName(String name) {
		headerName = name;
	}

	/**
	 * Set the header value to trigger a redirect.
	 * @param value the value
	 */
	public void setHeaderValue(String value) {
		headerValue = value;
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		super.afterPropertiesSet();
		Assert.hasLength(headerName, "Header name is required");
		Assert.hasLength(headerValue, "Header value is required");
	}
}
