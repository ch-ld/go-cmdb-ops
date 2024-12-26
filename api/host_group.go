// api/host_group.go
package api

import (
	"cmdb-ops-flow/models"
	"cmdb-ops-flow/service"
	"cmdb-ops-flow/utils/msg"
	"cmdb-ops-flow/utils/result"
	"github.com/gin-gonic/gin"
	"net/http"
	"strconv"
)

// 列表查询
func HostGroupList(c *gin.Context) {
	var input service.ListHostGroupsInput
	if err := c.ShouldBindQuery(&input); err != nil {
		c.JSON(http.StatusOK, (&result.Result{}).Error(msg.ERROR, err.Error(), msg.GetErrMsg(msg.ERROR)))
		return
	}
	groups, total, err := service.List(&input)
	if err != nil {
		c.JSON(http.StatusOK, (&result.Result{}).Error(msg.ERROR, err.Error(), msg.GetErrMsg(msg.ERROR)))
		return
	}
	// 定义响应结构体
	type Response struct {
		Items []models.HostGroup `json:"items"`
		Total int64              `json:"total"`
	}

	// 使用
	response := Response{
		Items: groups,
		Total: total,
	}

	code := msg.SUCCSE
	c.JSON(http.StatusOK, (&result.Result{}).Ok(code, response, msg.GetErrMsg(code)))
}

// 创建主机组
func HostGroupCreate(c *gin.Context) {
	var input service.CreateHostGroupInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusOK, (&result.Result{}).Error(msg.ERROR, err.Error(), msg.GetErrMsg(msg.ERROR)))
		return
	}

	group, err := service.Create(&input)
	if err != nil {
		c.JSON(http.StatusOK, (&result.Result{}).Error(msg.ERROR, err.Error(), msg.GetErrMsg(msg.ERROR)))
		return
	}
	code := msg.SUCCSE
	c.JSON(http.StatusOK, (&result.Result{}).Ok(code, group, msg.GetErrMsg(code)))
}

// 更新主机组
func HostGroupUpdate(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 32)

	var input service.UpdateHostGroupInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusOK, (&result.Result{}).Error(msg.ERROR, err.Error(), msg.GetErrMsg(msg.ERROR)))
		return
	}

	err := service.Update(uint(id), &input)
	if err != nil {
		c.JSON(http.StatusOK, (&result.Result{}).Error(msg.ERROR, err.Error(), msg.GetErrMsg(msg.ERROR)))
		return
	}

	code := msg.SUCCSE
	c.JSON(http.StatusOK, (&result.Result{}).Ok(code, "Success", msg.GetErrMsg(code)))
}

// 删除主机组
func HostGroupDelete(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 32)

	err := service.Delete(uint(id))
	if err != nil {
		c.JSON(http.StatusOK, (&result.Result{}).Error(msg.ERROR, err.Error(), msg.GetErrMsg(msg.ERROR)))
		return
	}

	code := msg.SUCCSE
	c.JSON(http.StatusOK, (&result.Result{}).Ok(code, "Success", msg.GetErrMsg(code)))
}
