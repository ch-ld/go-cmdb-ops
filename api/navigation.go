package api

import (
	"cmdb-ops-flow/models"
	"cmdb-ops-flow/service"
	"cmdb-ops-flow/utils/msg"
	"cmdb-ops-flow/utils/result"
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
)

func GetNavigationRecords(c *gin.Context) {
	list, err := service.GetNavigationRecords()
	if err != nil {
		c.JSON(http.StatusOK, (&result.Result{}).Error(msg.ERROR, err.Error(), msg.GetErrMsg(msg.ERROR)))
		return
	}
	code := 200
	c.JSON(http.StatusOK, (&result.Result{}).Ok(code, list, msg.GetErrMsg(code)))
}

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

func UpdateNavigationRecord(c *gin.Context) {
	var updatedRecord models.Navigation
	if err := c.ShouldBindJSON(&updatedRecord); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	fmt.Println("updatedRecord:", updatedRecord)

	data, err := service.UpdateNavigationRecord(updatedRecord)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	code := 200
	c.JSON(http.StatusOK, (&result.Result{}).Ok(code, data, msg.GetErrMsg(code)))
}

func DeleteNavigationRecord(c *gin.Context) {
	type DeleteRequest struct {
		ID uint `json:"id"` // 假设我们通过请求体传递 id
	}
	var req DeleteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	}
	fmt.Println("req:", req)
	//if err := db.Delete(&Navigation{}, id).Error; err != nil {
	//	c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	//	return
	//}
	// 将字符串转换为 uint64
	//id_int64, err := strconv.ParseUint(req.ID, 10, 0) // 10 表示基数，0 表示使用默认 bit size
	//if err != nil {
	//	fmt.Printf("转换错误: %v\n", err)
	//	return
	//}
	err := service.DeleteNavigationRecord(req.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	code := 200
	c.JSON(http.StatusOK, (&result.Result{}).Ok(code, "删除成功", msg.GetErrMsg(code)))
}

func SortNavigation(c *gin.Context) {
	var req struct {
		ID        uint   `json:"id"`
		Direction string `json:"direction"` // "up" 或 "down"
	}
	fmt.Println("req:", req)

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
