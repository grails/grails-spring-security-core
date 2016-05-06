package test

import grails.gorm.DetachedCriteria
import groovy.transform.ToString

import org.apache.commons.lang.builder.HashCodeBuilder

@ToString(cache=true, includeNames=true, includePackage=false)
class TestRoleGroupRoles implements Serializable {

	private static final long serialVersionUID = 1

	TestRoleGroup roleGroup
	TestRole role

	@Override
	boolean equals(other) {
		if (other instanceof TestRoleGroupRoles) {
			other.roleId == role?.id && other.roleGroupId == roleGroup?.id
		}
	}

	@Override
	int hashCode() {
		def builder = new HashCodeBuilder()
		if (roleGroup) builder.append(roleGroup.id)
		if (role) builder.append(role.id)
		builder.toHashCode()
	}

	static TestRoleGroupRoles get(long roleGroupId, long roleId) {
		criteriaFor(roleGroupId, roleId).get()
	}

	static boolean exists(long roleGroupId, long roleId) {
		criteriaFor(roleGroupId, roleId).count()
	}

	private static DetachedCriteria criteriaFor(long roleGroupId, long roleId) {
		TestRoleGroupRoles.where {
			roleGroup == TestRoleGroup.load(roleGroupId) &&
			role == TestRole.load(roleId)
		}
	}

	static TestRoleGroupRoles create(TestRoleGroup roleGroup, TestRole role) {
		def instance = new TestRoleGroupRoles(roleGroup: roleGroup, role: role)
		instance.save()
		instance
	}

	static boolean remove(TestRoleGroup rg, TestRole r) {
		if (rg && r) {
			TestRoleGroupRoles.where { roleGroup == rg && role == r }.deleteAll()
		}
	}

	static int removeAll(TestRole r) {
		r ? TestRoleGroupRoles.where { role == r }.deleteAll() : 0
	}

	static int removeAll(TestRoleGroup rg) {
		rg ? TestRoleGroupRoles.where { roleGroup == rg }.deleteAll() : 0
	}

	static constraints = {
		role validator: { TestRole r, TestRoleGroupRoles rg ->
			if (rg.roleGroup?.id) {
				TestRoleGroupRoles.withNewSession {
					if (TestRoleGroupRoles.exists(rg.roleGroup.id, r.id)) {
						return ['roleGroup.exists']
					}
				}
			}
		}
	}

	static mapping = {
		id composite: ['roleGroup', 'role']
		version false
	}
}
