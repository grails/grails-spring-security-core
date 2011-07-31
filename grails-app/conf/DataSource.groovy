dataSource {
	pooled = true
	driverClassName = 'org.hsqldb.jdbcDriver'
	username = 'sa'
	password = ''
	dbCreate = 'update'
	url = 'jdbc:hsqldb:mem:testDb'
}

hibernate {
	cache.use_second_level_cache = false
	cache.use_query_cache = false
	cache.provider_class = 'org.hibernate.cache.EhCacheProvider'
}
