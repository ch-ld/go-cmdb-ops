package api

import (
	"cmdb-ops-flow/models"
	"cmdb-ops-flow/service"
	"cmdb-ops-flow/utils/msg"
	"cmdb-ops-flow/utils/result"
	"github.com/gin-gonic/gin"
	"net/http"
)

// 获取导航栏记录
func GetNavigationRecords(c *gin.Context) {
	list, err := service.GetNavigationRecords()
	if err != nil {
		c.JSON(http.StatusOK, (&result.Result{}).Error(msg.ERROR, err.Error(), msg.GetErrMsg(msg.ERROR)))
		return
	}
	code := 200
	c.JSON(http.StatusOK, (&result.Result{}).Ok(code, list, msg.GetErrMsg(code)))
}

// 创建导航栏记录
func CreateNavigationRecord(c *gin.Context) {
	var newRecord models.Navigation
	if err := c.ShouldBindJSON(&newRecord); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	data, err := service.CreateNavigationRecord(newRecord)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	code := 200
	c.JSON(http.StatusOK, (&result.Result{}).Ok(code, data, msg.GetErrMsg(code)))
}

// 更新导航栏记录
func UpdateNavigationRecord(c *gin.Context) {
	var updatedRecord models.Navigation
	if err := c.ShouldBindJSON(&updatedRecord); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	data, err := service.UpdateNavigationRecord(updatedRecord)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	code := 200
	c.JSON(http.StatusOK, (&result.Result{}).Ok(code, data, msg.GetErrMsg(code)))
}

// 删除导航栏记录
func DeleteNavigationRecord(c *gin.Context) {
	type DeleteRequest struct {
		ID uint `json:"id"` // 假设我们通过请求体传递 id
	}
	var req DeleteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	}

	err := service.DeleteNavigationRecord(req.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	code := 200
	c.JSON(http.StatusOK, (&result.Result{}).Ok(code, "删除成功", msg.GetErrMsg(code)))
}

// 导航栏记录排序
func SortNavigation(c *gin.Context) {
	var req struct {
		ID        uint   `json:"id"`
		Direction string `json:"direction"` // "up" 或 "down"
	}

	// 绑定请求的 JSON 数据
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 调用服务层的排序函数
	err := models.SortNavigationRecord(req.ID, req.Direction)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	code := 200
	c.JSON(http.StatusOK, (&result.Result{}).Ok(code, "Sort successful", msg.GetErrMsg(code)))
}
