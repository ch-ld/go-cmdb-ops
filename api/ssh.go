package api

import (
	"cmdb-ops-flow/conf"
	"cmdb-ops-flow/models"
	"cmdb-ops-flow/utils/common"
	"cmdb-ops-flow/utils/msg"
	"cmdb-ops-flow/utils/result"
	"cmdb-ops-flow/utils/ssh"
	"encoding/base64"
	"fmt"
	"github.com/gin-gonic/gin"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Query 查询参数
type SshCmd struct {
	HostId  int    `json:"hostId"`
	Command string `json:"command"`
}

type SftpCmd struct {
	HostId int    `json:"hostId"`
	Path   string `json:"path"`
}

func SftpListDirectory(c *gin.Context) {
	hostID := c.Query("hostId")
	if hostID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "hostId不能为空"})
		return
	}
	UintHostID, err := strconv.ParseUint(hostID, 10, 0)
	if err != nil {
		fmt.Println("转换错误:", err)
		return
	}
	host, _ := models.HostGetByID(uint(UintHostID))
	key, err := base64.StdEncoding.DecodeString(conf.Encryptkey)
	password, err := common.Decrypt(key, host.SSHPassword)
	if err != nil {
		fmt.Println("解密失败:", err)
		return
	}
	config := &ssh.SSHClientConfig{
		Timeout:   time.Second * 5,
		IP:        host.PrivateIP,
		Port:      host.SSHPort,
		UserName:  host.SSHUser,
		Password:  password,
		AuthModel: "PASSWORD",
	}

	path := c.Query("path")
	if path == "" {
		path = "/home/" + host.SSHUser
	}
	// 创建SFTP客户端
	sftpClient, err := ssh.NewSFTPClient(config)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer sftpClient.Close()

	// 获取目录列表
	files, err := sftpClient.ListDir(path)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"code": 200,
		"data": files,
		"path": path,
	})
}

func SftpUploadFile(c *gin.Context) {
	// 获取表单参数
	file, header, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "获取上传文件失败: " + err.Error()})
		return
	}
	defer file.Close()

	// 获取目标路径参数
	remotePath := c.PostForm("path")
	if remotePath == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "目标路径不能为空"})
		return
	}

	hostID := c.PostForm("hostId")
	if hostID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "hostId不能为空"})
		return
	}
	UintHostID, err := strconv.ParseUint(hostID, 10, 0)
	if err != nil {
		fmt.Println("转换错误:", err)
		return
	}
	host, _ := models.HostGetByID(uint(UintHostID))
	key, err := base64.StdEncoding.DecodeString(conf.Encryptkey)
	password, err := common.Decrypt(key, host.SSHPassword)
	if err != nil {
		fmt.Println("解密失败:", err)
		return
	}
	config := &ssh.SSHClientConfig{
		Timeout:   time.Second * 5,
		IP:        host.PrivateIP,
		Port:      host.SSHPort,
		UserName:  host.SSHUser,
		Password:  password,
		AuthModel: "PASSWORD",
	}

	// 创建临时文件
	tempFile := filepath.Join(os.TempDir(), header.Filename)
	out, err := os.Create(tempFile)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer os.Remove(tempFile)
	defer out.Close()

	// 保存文件
	_, err = io.Copy(out, file)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 创建SFTP客户端并上传文件
	sftpClient, err := ssh.NewSFTPClient(config)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer sftpClient.Close()

	remoteFilePath := filepath.Join(remotePath, header.Filename)
	err, remotePath = sftpClient.UploadFile(tempFile, remoteFilePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 200,
		"msg":  "文件上传成功",
		"data": remotePath,
	})
}

func SftpDownloadFile(c *gin.Context) {
	hostID := c.Query("hostId")
	if hostID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "hostId不能为空"})
		return
	}
	UintHostID, err := strconv.ParseUint(hostID, 10, 0)
	if err != nil {
		fmt.Println("转换错误:", err)
		return
	}
	host, _ := models.HostGetByID(uint(UintHostID))
	key, err := base64.StdEncoding.DecodeString(conf.Encryptkey)
	password, err := common.Decrypt(key, host.SSHPassword)
	if err != nil {
		fmt.Println("解密失败:", err)
		return
	}
	config := &ssh.SSHClientConfig{
		Timeout:   time.Second * 5,
		IP:        host.PrivateIP,
		Port:      host.SSHPort,
		UserName:  host.SSHUser,
		Password:  password,
		AuthModel: "PASSWORD",
	}

	remotePath := c.Query("path")

	// 创建SFTP客户端
	sftpClient, err := ssh.NewSFTPClient(config)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer sftpClient.Close()

	// 打开远程文件
	remoteFile, err := sftpClient.Open(remotePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer remoteFile.Close()

	// 获取文件信息
	fileInfo, err := remoteFile.Stat()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 设置响应头
	c.Header("Content-Description", "File Transfer")
	c.Header("Content-Transfer-Encoding", "binary")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filepath.Base(remotePath)))
	c.Header("Content-Type", "application/octet-stream")
	c.Header("Content-Length", fmt.Sprintf("%d", fileInfo.Size()))

	// 发送文件内容
	c.Stream(func(w io.Writer) bool {
		_, err := io.Copy(w, remoteFile)
		return err == nil
	})
}

// CreateDirectory 创建目录
func SftpCreateDirectory(c *gin.Context) {
	var r SftpCmd
	if err := c.ShouldBind(&r); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	hostID := r.HostId
	if hostID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "hostId不能为空"})
		return
	}
	host, _ := models.HostGetByID(uint(hostID))
	key, err := base64.StdEncoding.DecodeString(conf.Encryptkey)
	password, err := common.Decrypt(key, host.SSHPassword)
	if err != nil {
		fmt.Println("解密失败:", err)
		return
	}
	config := &ssh.SSHClientConfig{
		Timeout:   time.Second * 5,
		IP:        host.PrivateIP,
		Port:      host.SSHPort,
		UserName:  host.SSHUser,
		Password:  password,
		AuthModel: "PASSWORD",
	}

	// 创建SFTP客户端
	sftpClient, err := ssh.NewSFTPClient(config)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer sftpClient.Close()

	// 创建目录
	err = sftpClient.MakeDir(r.Path)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 200,
		"msg":  "目录创建成功",
		"data": r.Path,
	})
}

// DeletePath 删除文件或目录
func SftpDeletePath(c *gin.Context) {
	var r SftpCmd
	if err := c.ShouldBind(&r); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	hostID := r.HostId
	if hostID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "hostId不能为空"})
		return
	}
	host, _ := models.HostGetByID(uint(hostID))
	key, err := base64.StdEncoding.DecodeString(conf.Encryptkey)
	password, err := common.Decrypt(key, host.SSHPassword)
	if err != nil {
		fmt.Println("解密失败:", err)
		return
	}
	config := &ssh.SSHClientConfig{
		Timeout:   time.Second * 5,
		IP:        host.PrivateIP,
		Port:      host.SSHPort,
		UserName:  host.SSHUser,
		Password:  password,
		AuthModel: "PASSWORD",
	}

	// 创建SFTP客户端
	sftpClient, err := ssh.NewSFTPClient(config)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer sftpClient.Close()

	// 获取文件信息
	fileInfo, err := sftpClient.Stat(r.Path)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 如果是目录，递归删除
	if fileInfo.IsDir() {
		err = sftpClient.RemoveDirectory(r.Path)
	} else {
		err = sftpClient.Remove(r.Path)
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 200,
		"msg":  "删除成功",
		"data": r.Path,
	})
}

func SshCommand(c *gin.Context) {
	var r SshCmd
	// 绑定并校验请求参数
	if err := c.ShouldBind(&r); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"err": err.Error(),
		})
		return
	}
	host, _ := models.HostGetByID(uint(r.HostId))
	key, err := base64.StdEncoding.DecodeString(conf.Encryptkey)
	password, err := common.Decrypt(key, host.SSHPassword)
	if err != nil {
		fmt.Println("解密失败:", err)
		return
	}
	config := &ssh.SSHClientConfig{
		Timeout:   time.Second * 5,
		IP:        host.PrivateIP,
		Port:      host.SSHPort,
		UserName:  host.SSHUser,
		Password:  password,
		AuthModel: "PASSWORD",
	}

	// 开始处理 SSH 会话
	output, err := ssh.SshCommand(config, r.Command)
	if err != nil {
		c.JSON(http.StatusOK, (&result.Result{}).Error(msg.ERROR, err.Error(), msg.GetErrMsg(msg.ERROR)))
		return
	}
	formattedOutput := strings.ReplaceAll(output, "\n", "<br>")

	c.JSON(http.StatusOK, (&result.Result{}).Ok(200, formattedOutput, msg.GetErrMsg(200)))

}
