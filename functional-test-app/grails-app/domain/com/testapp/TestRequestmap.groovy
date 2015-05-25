package com.testapp

import groovy.transform.ToString

import org.apache.commons.lang.builder.HashCodeBuilder
import org.springframework.http.HttpMethod

@ToString(cache=true, includeNames=true, includePackage=false)
class TestRequestmap implements Serializable {

	private static final long serialVersionUID = 1

	String configAttribute
	HttpMethod httpMethod
	String url

	TestRequestmap(String url, String configAttribute, HttpMethod httpMethod = null) {
		this()
		this.configAttribute = configAttribute
		this.httpMethod = httpMethod
		this.url = url
	}

	@Override
	int hashCode() {
		new HashCodeBuilder().append(configAttribute).append(httpMethod).append(url).toHashCode()
	}

	@Override
	boolean equals(other) {
		is(other) || (
			other instanceof TestRequestmap &&
			other.configAttribute == configAttribute &&
			other.httpMethod == httpMethod &&
			other.url == url)
	}

	static constraints = {
		configAttribute blank: false
		httpMethod nullable: true
		url blank: false, unique: 'httpMethod'
	}

	static mapping = {
		cache true
	}
}
