dataSource {
	pooled = true
	driverClassName = 'org.h2.Driver'
	username = 'sa'
	password = ''
	dbCreate = 'update'
	url = 'jdbc:h2:mem:testDb;MVCC=TRUE;LOCK_TIMEOUT=10000;DB_CLOSE_ON_EXIT=FALSE'
	logSql = true
}

hibernate {
	cache.use_second_level_cache = false
	cache.use_query_cache = false
	cache.provider_class = 'org.hibernate.cache.EhCacheProvider'
	format_sql = true
	use_sql_comments = true
}
