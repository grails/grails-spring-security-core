/* Copyright 2011-2015 SpringSource.
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
package grails.plugin.springsecurity
import grails.config.Config
import grails.core.DefaultGrailsApplication

/**
 * For testing only.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class FakeApplication extends DefaultGrailsApplication {

	final ConfigObject config = new ConfigObject()

	FakeApplication() {}

	@SuppressWarnings("rawtypes")
	FakeApplication(Class[] classes, ClassLoader classLoader) {
		super(classes, classLoader)
	}

	@Override
	ConfigObject getConfig() { config }
}
