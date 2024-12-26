package api

import (
	"cmdb-ops-flow/models"
	"cmdb-ops-flow/service"
	"cmdb-ops-flow/utils/msg"
	"cmdb-ops-flow/utils/result"
	"github.com/gin-gonic/gin"
	"net/http"
)

func GetRole(c *gin.Context) {
	list, err := service.GetRole()
	if err != nil {
		c.JSON(http.StatusOK, (&result.Result{}).Error(msg.ERROR, err.Error(), msg.GetErrMsg(msg.ERROR)))
		return
	}
	code := 200
	c.JSON(http.StatusOK, (&result.Result{}).Ok(code, list, msg.GetErrMsg(code)))
}

func DelRole(c *gin.Context) {
	var data models.Role
	if err := c.ShouldBindJSON(&data); err != nil {
		c.JSON(http.StatusOK, (&result.Result{}).Error(msg.ERROR, err.Error(), msg.GetErrMsg(msg.ERROR)))
		return
	}
	code := models.DelRole(data.ID)

	c.JSON(http.StatusOK, (&result.Result{}).Ok(code, data, msg.GetErrMsg(code)))
}

func AddRole(c *gin.Context) {
	var data models.Role
	if err := c.ShouldBindJSON(&data); err != nil {
		c.JSON(http.StatusOK, (&result.Result{}).Error(msg.ERROR, err.Error(), msg.GetErrMsg(msg.ERROR)))
		return
	}
	if data.RoleName == "" {
		c.JSON(http.StatusOK, (&result.Result{}).Error(msg.ERROR, nil, msg.GetErrMsg(msg.ERROR_USER_NO_PASSWD)))
		return
	}
	code := models.CheckRole(data.RoleName)
	if code == msg.SUCCSE {
		service.AddRole(data)
	}
	c.JSON(http.StatusOK, (&result.Result{}).Ok(code, data, msg.GetErrMsg(code)))
}
