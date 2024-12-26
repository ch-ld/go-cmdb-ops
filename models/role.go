package models

import (
	"cmdb-ops-flow/utils/msg"
	"fmt"
)

// 角色表
type Role struct {
	ID       int    `gorm:"primary_key"`
	RoleName string `json:"role_name" :"role_name"`
	Users    []User `gorm:"many2many:user_roles"`
}

//// 用户角色关联表
//type UserRole struct {
//	UserId int `json:"user_id" :"user_id"`
//	RoleId int `json:"role_id" :"role_id"`
//}

func InitRoleData() {
	// 若表不存在，则创建
	db.AutoMigrate(&Role{})
	// 若表存在，则检查是否有初始数据
	var count int64
	db.Model(&Role{}).Count(&count)
	if count > 0 {
		fmt.Println("Role表中已有初始数据，跳过")
	} else {
		roles := []Role{
			{RoleName: "admin"},
			{RoleName: "editor"},
			{RoleName: "user"},
			{RoleName: "guest"},
		}
		for _, role := range roles {
			db.Create(&role)
		}
	}
}

func GetRole() (data interface{}, err error) {
	var list []Role
	res := db.Debug().Find(&list)
	return list, res.Error
}

func DelRole(name int) (code int) {
	var role Role
	role.ID = name
	//db.Select("id").Where("userid = ?", name).First(&role)
	//db.First(&role)
	if role.ID > 0 {
		err = db.Delete(&role).Error
		if err != nil {
			return msg.ERROR_USER_NOT_EXIST
		}
		return msg.SUCCSE
	} else {
		return msg.ERROR
	}
}

func CheckRole(name string) (code int) {
	var role Role
	db.Select("id").Where("role_name = ?", name).First(&role)
	if role.ID > 0 {
		return msg.ERROR_USERNAME_USED
	}
	return msg.SUCCSE
}

func AddRole(role Role) (interface{}, error) {
	err := db.Create(&role).Error
	return role, err
}
