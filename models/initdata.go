package models

func InitDbData() {
	InitRoleData()
	InitMenuData()
	InitNavigationData()
	//InitUserData()
}

//func InitUserData() {
//	admin := User{
//		Username: "admin",
//		Password: "123456",
//	}
//
//	_, err2 := service.AddUser(admin)
//	if err2 != nil {
//		return
//	}
//}
