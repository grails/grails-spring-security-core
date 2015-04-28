dataSource {
	pooled = true
	jmxExport = true
	driverClassName = 'org.h2.Driver'
	username = 'sa'
	password = ''
	dbCreate = 'update'
	url = 'jdbc:h2:mem:testDb;MVCC=TRUE;LOCK_TIMEOUT=10000;DB_CLOSE_ON_EXIT=FALSE'
}
hibernate {
	cache.use_second_level_cache = false
	cache.use_query_cache = false
	cache.region.factory_class = 'net.sf.ehcache.hibernate.EhCacheRegionFactory'
	singleSession = true
}
