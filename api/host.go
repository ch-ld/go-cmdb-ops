package api

import (
	"cmdb-ops-flow/models"
	"cmdb-ops-flow/service"
	"cmdb-ops-flow/utils/msg"
	"cmdb-ops-flow/utils/result"
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
	"strconv"
)

// List 获取主机列表
func HostsList(c *gin.Context) {
	var query service.ListHostInput
	if err := c.ShouldBindQuery(&query); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	hosts, total, err := service.HostsList(&query)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	// 定义响应结构体
	type Response struct {
		List  []models.Host `json:"list"`
		Total int64         `json:"total"`
	}
	response := Response{
		List:  hosts,
		Total: total,
	}
	code := 200
	c.JSON(http.StatusOK, (&result.Result{}).Ok(code, response, msg.GetErrMsg(code)))
}

// Create 创建主机
func HostCreate(c *gin.Context) {
	var input service.CreateHostInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	host, err := service.HostCreate(&input)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	code := msg.SUCCSE
	c.JSON(http.StatusOK, (&result.Result{}).Ok(code, host, msg.GetErrMsg(code)))
}

// Get 获取主机详情
//func  Get(c *gin.Context) {
//	id := c.Param("id")
//	host, err := h.hostService.Get(id)
//	if err != nil {
//		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
//		return
//	}
//	c.JSON(http.StatusOK, host)
//}

// Update 更新主机
func HostUpdate(c *gin.Context) {
	id := c.Param("id")
	var input service.UpdateHostInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	host, err := service.HostUpdate(id, &input)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	code := msg.SUCCSE
	c.JSON(http.StatusOK, (&result.Result{}).Ok(code, host, msg.GetErrMsg(code)))
}

// Delete 删除主机
func HostDelete(c *gin.Context) {
	id := c.Param("id")
	// 将字符串转换为 uint
	ID, _ := strconv.ParseUint(id, 10, 64)

	err := service.HostDelete(uint(ID))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	code := msg.SUCCSE
	c.JSON(http.StatusOK, (&result.Result{}).Ok(code, "Secs", msg.GetErrMsg(code)))
}

// BatchDelete 批量删除主机
func HostBatchDelete(c *gin.Context) {
	var input struct {
		IDs []string `json:"ids" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 创建一个等长的 uint 切片
	uintIDs := make([]uint, len(input.IDs))

	// 转换每个元素
	for i, idStr := range input.IDs {
		id, err := strconv.ParseUint(idStr, 10, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Invalid ID format at position %d: %s", i, idStr)})
			return
		}
		uintIDs[i] = uint(id)
	}

	err := service.HostBatchDelete(uintIDs)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	code := msg.SUCCSE
	c.JSON(http.StatusOK, (&result.Result{}).Ok(code, "Secs", msg.GetErrMsg(code)))
}

// Import 导入主机
func HostsImport(c *gin.Context) {
	//file, err := c.FormFile("file")
	//if err != nil {
	//	c.JSON(http.StatusBadRequest, gin.H{"error": "请选择要上传的文件"})
	//	return
	//}
	//
	//err = service.HostsImport(file)
	//if err != nil {
	//	c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	//	return
	//}

	code := msg.SUCCSE
	c.JSON(http.StatusOK, (&result.Result{}).Ok(code, "Secs", msg.GetErrMsg(code)))
}

// 生成Excel模版文件
func ExportTemplate(c *gin.Context) {
	// 生成Excel模板
	buffer, err := service.GetImportTemplate()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code": 500,
			"msg":  "生成模板失败: " + err.Error(),
		})
		return
	}

	// 设置响应头，让浏览器下载文件
	c.Header("Content-Description", "File Transfer")
	c.Header("Content-Disposition", "attachment; filename=host_import_template.xlsx")
	c.Header("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	c.Header("Content-Transfer-Encoding", "binary")
	c.Header("Expires", "0")
	c.Header("Cache-Control", "must-revalidate")
	c.Header("Pragma", "public")

	// 直接将buffer写入响应
	c.Data(http.StatusOK, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", buffer.Bytes())
}

// SyncCloud 同步云主机
func SyncCloud(c *gin.Context) {
	//var input service.SyncCloudHostsInput
	//if err := c.ShouldBindJSON(&input); err != nil {
	//	c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	//	return
	//}

	//err := service.SyncCloudHosts(&input)
	//if err != nil {
	//	c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	//	return
	//}

	c.JSON(http.StatusOK, gin.H{"message": "success"})
}
