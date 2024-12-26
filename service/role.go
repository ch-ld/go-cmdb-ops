package service

import (
	"cmdb-ops-flow/models"
)

func GetRole() (data interface{}, err error) {
	return models.GetRole()
}

func AddRole(role models.Role) (data interface{}, err error) {
	daoRole := models.Role{
		RoleName: role.RoleName,
	}
	data, err = models.AddRole(daoRole)
	return data, err
}
