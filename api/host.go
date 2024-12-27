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
	"strings"
)

// SyncCloudRequest 同步云主机请求结构
type SyncCloudRequest struct {
	Provider     string   `json:"provider" binding:"required,oneof=aliyun aws"`
	AccessKey    string   `json:"accessKey" binding:"required"`
	AccessSecret string   `json:"accessSecret" binding:"required"`
	Regions      []string `json:"regions" binding:"required,min=1"`
	HostGroupId  int      `json:"hostGroupId" binding:"required"`
}

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
func HostsBatchDelete(c *gin.Context) {
	var input struct {
		IDs []int `json:"ids" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 创建一个等长的 uint 切片
	uintIDs := make([]uint, len(input.IDs))

	// 转换每个元素
	for i, idInt := range input.IDs {
		uintIDs[i] = uint(idInt)
	}

	err := service.HostBatchDelete(uintIDs)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	code := msg.SUCCSE
	c.JSON(http.StatusOK, (&result.Result{}).Ok(code, "Secs", msg.GetErrMsg(code)))
}

func HostsImport(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, (&result.Result{}).Error(msg.ERROR, nil, "请选择要上传的文件"))
		return
	}

	// 验证文件类型
	filename := strings.ToLower(file.Filename)
	if !strings.HasSuffix(filename, ".csv") &&
		!strings.HasSuffix(filename, ".xlsx") &&
		!strings.HasSuffix(filename, ".xls") {
		c.JSON(http.StatusBadRequest, (&result.Result{}).Error(msg.ERROR, nil, "只支持 CSV、XLSX 和 XLS 格式文件"))
		return
	}

	// 验证文件大小
	if file.Size > 10<<20 {
		c.JSON(http.StatusBadRequest, (&result.Result{}).Error(msg.ERROR, nil, "文件大小不能超过10MB"))
		return
	}

	fileReader, err := file.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, (&result.Result{}).Error(msg.ERROR, nil, "无法打开文件"))
		return
	}
	defer fileReader.Close()

	// 添加 panic 恢复
	defer func() {
		if r := recover(); r != nil {
			c.JSON(http.StatusInternalServerError, (&result.Result{}).Error(msg.ERROR, nil, fmt.Sprintf("导入过程发生错误: %v", r)))
		}
	}()

	err = service.HostsImport(fileReader, file.Filename)
	if err != nil {
		c.JSON(http.StatusBadRequest, (&result.Result{}).Error(msg.ERROR, nil, err.Error()))
		return
	}

	c.JSON(http.StatusOK, (&result.Result{}).Ok(msg.SUCCSE, nil, "导入成功"))
}

func HostsCheck(c *gin.Context) {
	id := c.Param("id")
	intID, err := strconv.Atoi(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的 ID"})
		return
	}
	err = service.CollectHostInfo(uint(intID))
	if err != nil {
		c.JSON(http.StatusInternalServerError, (&result.Result{}).Ok(msg.ERROR, nil, err.Error()))
		return
	}

	c.JSON(http.StatusOK, (&result.Result{}).Ok(msg.SUCCSE, nil, "检测完成"))
}

// SyncCloud 同步云主机
func HostsSyncCloud(c *gin.Context) {
	var req SyncCloudRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusInternalServerError, (&result.Result{}).Ok(msg.ERROR, nil, "参数验证失败"))
		return
	}

	config := map[string]string{
		"accessKey":    req.AccessKey,
		"accessSecret": req.AccessSecret,
		"regions":      strings.Join(req.Regions, ","),
	}

	if err := service.SyncCloudHosts(req.Provider, config, req.HostGroupId); err != nil {
		c.JSON(http.StatusInternalServerError, (&result.Result{}).Ok(msg.ERROR, nil, err.Error()))
		return
	}

	c.JSON(http.StatusOK, (&result.Result{}).Ok(msg.SUCCSE, nil, "同步成功"))
}

// 生成Excel模版文件 前端实现
//func ExportTemplate(c *gin.Context) {
//	// 生成Excel模板
//	buffer, err := service.GetImportTemplate()
//	if err != nil {
//		c.JSON(http.StatusInternalServerError, gin.H{
//			"code": 500,
//			"msg":  "生成模板失败: " + err.Error(),
//		})
//		return
//	}
//
//	// 设置响应头，让浏览器下载文件
//	c.Header("Content-Description", "File Transfer")
//	c.Header("Content-Disposition", "attachment; filename=host_import_template.xlsx")
//	c.Header("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
//	c.Header("Content-Transfer-Encoding", "binary")
//	c.Header("Expires", "0")
//	c.Header("Cache-Control", "must-revalidate")
//	c.Header("Pragma", "public")
//
//	// 直接将buffer写入响应
//	c.Data(http.StatusOK, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", buffer.Bytes())
//}

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
