package apis_k8s

import (
	"cmdb-ops-flow/service/service_k8s"
	"cmdb-ops-flow/utils/msg"
	"cmdb-ops-flow/utils/result"
	"github.com/gin-gonic/gin"
	"net/http"
)

func GetVersion(c *gin.Context) {
	var data struct {
		ID int `json:"id"`
	}
	if err := c.ShouldBindJSON(&data); err != nil {
		c.JSON(http.StatusOK, (&result.Result{}).Error(400, err.Error(), msg.GetErrMsg(msg.ERROR)))
		return
	}
	list, err := service_k8s.Version(data.ID)
	if err != nil {
		c.JSON(http.StatusOK, (&result.Result{}).Error(msg.ERROR, err.Error(), msg.GetErrMsg(msg.ERROR)))
		return
	}
	code := msg.SUCCSE
	c.JSON(http.StatusOK, (&result.Result{}).Ok(code, list, msg.GetErrMsg(code)))
}

func GetAllNodes(c *gin.Context) {
	var data struct {
		ID int `json:"id"`
	}
	if err := c.ShouldBindJSON(&data); err != nil {
		c.JSON(http.StatusOK, (&result.Result{}).Error(400, err.Error(), msg.GetErrMsg(msg.ERROR)))
		return
	}
	list, err := service_k8s.Getnodes(data.ID)
	if err != nil {
		c.JSON(http.StatusOK, (&result.Result{}).Error(msg.ERROR, err.Error(), msg.GetErrMsg(msg.ERROR)))
		return
	}
	code := msg.SUCCSE
	c.JSON(http.StatusOK, (&result.Result{}).Ok(code, list, msg.GetErrMsg(code)))
}