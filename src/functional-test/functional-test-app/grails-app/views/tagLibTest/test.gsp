<html>
<body>

	<sec:ifAllGranted roles='ROLE_USER,ROLE_ADMIN'>user and admin</sec:ifAllGranted><br/>
	<sec:ifAllGranted roles='ROLE_USER,ROLE_ADMIN,ROLE_FOO'>user and admin and foo</sec:ifAllGranted><br/>

	<sec:ifNotGranted roles='ROLE_USER,ROLE_ADMIN'>not user and not admin</sec:ifNotGranted><br/>

	<sec:ifAnyGranted roles='ROLE_USER,ROLE_ADMIN'>user or admin</sec:ifAnyGranted><br/>

	accountNonExpired: "<sec:loggedInUserInfo field='accountNonExpired'>not logged in</sec:loggedInUserInfo>"<br/>
	id: "<sec:loggedInUserInfo field='id'>not logged in</sec:loggedInUserInfo>"<br/>

	Username is "<sec:username/>"<br/>

	<sec:ifLoggedIn>logged in true</sec:ifLoggedIn><br/>
	<sec:ifNotLoggedIn>logged in false</sec:ifNotLoggedIn><br/>

	<sec:ifSwitched>switched true</sec:ifSwitched><br/>
	<sec:ifNotSwitched>switched false</sec:ifNotSwitched><br/>
	switched original username "<sec:switchedUserOriginalUsername/>"<br/>

	<sec:access   expression="hasRole('ROLE_USER')">access with role user: true</sec:access><br/>
	<sec:noAccess expression="hasRole('ROLE_USER')">access with role user: false</sec:noAccess><br/>

	<sec:access   expression="hasRole('ROLE_ADMIN')">access with role admin: true</sec:access><br/>
	<sec:noAccess expression="hasRole('ROLE_ADMIN')">access with role admin: false</sec:noAccess><br/>

	<sec:access   expression="hasRole('ROLE_ANONYMOUS')">anonymous access: true</sec:access><br/>
	<sec:noAccess expression="hasRole('ROLE_ANONYMOUS')">anonymous access: false</sec:noAccess><br/>

	<sec:access   url='/tagLibTest/test'>Can access /tagLibTest/test</sec:access><br/>
	<sec:noAccess url='/tagLibTest/test'>Cannot access /tagLibTest/test</sec:noAccess><br/>
	<sec:access   url='/tag-lib-test/test'>Can access /tag-lib-test/test</sec:access><br/>
	<sec:noAccess url='/tag-lib-test/test'>Cannot access /tag-lib-test/test</sec:noAccess><br/>

	<sec:access   url='/login/auth'>Can access /login/auth</sec:access><br/>
	<sec:noAccess url='/login/auth'>Cannot access /login/auth</sec:noAccess><br/>

	<sec:access   url='/secureAnnotated'>Can access /secureAnnotated</sec:access><br/>
	<sec:noAccess url='/secureAnnotated'>Cannot access /secureAnnotated</sec:noAccess><br/>
	<sec:access   url='/secure-annotated'>Can access /secure-annotated</sec:access><br/>
	<sec:noAccess url='/secure-annotated'>Cannot access /secure-annotated</sec:noAccess><br/>

</body>
</html>
