package service

import (
	"bytes"
	"cmdb-ops-flow/conf"
	"cmdb-ops-flow/models"
	"cmdb-ops-flow/utils/common"
	"encoding/base64"
	"encoding/csv"
	"errors"
	"fmt"
	"github.com/xuri/excelize/v2"
	"io"
	"log"
	"strconv"
	"strings"
)

type CreateHostInput struct {
	HostGroupID uint               `json:"hostGroupId" binding:"required"`
	Hostname    string             `json:"hostname" binding:"required"`
	PrivateIP   string             `json:"privateIp" binding:"required,ip"`
	PublicIP    string             `json:"publicIp" binding:"omitempty,ip"`
	SSHPort     int                `json:"sshPort" binding:"required,min=1,max=65535"`
	SSHUser     string             `json:"sshUser" binding:"required"`
	SSHAuthType models.SSHAuthType `json:"sshAuthType" binding:"required,oneof=password key"`
	SSHPassword string             `json:"sshPassword"`
	SSHKey      string             `json:"sshKey"`
	OSType      string             `json:"osType" binding:"required"`
	OSVersion   string             `json:"osVersion"`
	Tags        []string           `json:"tags"`
	Description string             `json:"description"`
	Region      string             `json:"region"`
}

type UpdateHostInput struct {
	HostGroupID *uint               `json:"hostGroupId"`
	Hostname    *string             `json:"hostname"`
	PrivateIP   *string             `json:"privateIp" binding:"omitempty,ip"`
	PublicIP    *string             `json:"publicIp" binding:"omitempty,ip"`
	SSHPort     *int                `json:"sshPort" binding:"omitempty,min=1,max=65535"`
	SSHUser     *string             `json:"sshUser"`
	SSHAuthType *models.SSHAuthType `json:"sshAuthType" binding:"omitempty,oneof=password key"`
	SSHPassword string              `json:"sshPassword"`
	SSHKey      *string             `json:"sshKey"`
	OSType      *string             `json:"osType"`
	OSVersion   *string             `json:"osVersion"`
	Tags        []string            `json:"tags"`
	Region      *string             `json:"region"`
	Description *string             `json:"description"`
}

type ListHostInput struct {
	HostGroupID uint   `form:"hostGroupId"`
	Keyword     string `form:"keyword"`
	Status      string `form:"status"`
	Page        int    `form:"page" binding:"required,min=1"`
	PageSize    int    `form:"pageSize" binding:"required,min=1,max=100"`
}

// 创建主机
func HostCreate(input *CreateHostInput) (*models.Host, error) {
	// 验证SSH认证信息
	if input.SSHAuthType == models.SSHAuthPassword && input.SSHPassword == "" {
		return nil, errors.New("SSH password is required when using password authentication")
	}

	if input.SSHAuthType == models.SSHAuthKey && input.SSHKey == "" {
		return nil, errors.New("SSH key is required when using key authentication")
	}
	fmt.Println("input:", input)

	//key := []byte(conf.Encryptkey)
	// 解码 Base64 密钥
	key, err := base64.StdEncoding.DecodeString(conf.Encryptkey)
	if err != nil {
		// 处理解码错误
		return nil, fmt.Errorf("failed to decode encryption key: %v", err)
	}
	password, err := common.Encrypt(key, input.SSHPassword)

	if err != nil {
		fmt.Println(err)
	}

	// 创建主机记录
	host := &models.Host{
		HostGroupID: input.HostGroupID,
		Hostname:    input.Hostname,
		PrivateIP:   input.PrivateIP,
		PublicIP:    input.PublicIP,
		SSHPort:     input.SSHPort,
		SSHUser:     input.SSHUser,
		SSHAuthType: input.SSHAuthType,
		SSHPassword: password,
		SSHKey:      input.SSHKey,
		OSType:      input.OSType,
		OSVersion:   input.OSVersion,
		Tags:        strings.Join(input.Tags, ","),
		Description: input.Description,
		Region:      input.Region,
		Source:      models.HostSourceManual,
		Status:      models.HostStatusUnknown,
	}

	// 创建主机
	if err := models.HostCreate(host); err != nil {
		return nil, err
	}

	// 异步执行SSH连接测试和信息收集
	//go collectHostInfo(host)

	return host, nil
}

// 更新主机
func HostUpdate(id string, input *UpdateHostInput) (*models.Host, error) {

	// 构建更新数据
	updates := models.Host{}
	if input.HostGroupID != nil {
		updates.HostGroupID = *input.HostGroupID
	}
	if input.Hostname != nil {
		updates.Hostname = *input.Hostname
	}
	if input.PrivateIP != nil {
		updates.PrivateIP = *input.PrivateIP
	}
	if input.PublicIP != nil {
		updates.PublicIP = *input.PublicIP
	}
	if input.SSHPort != nil {
		updates.SSHPort = *input.SSHPort
	}
	if input.SSHUser != nil {
		updates.SSHUser = *input.SSHUser
	}
	if input.SSHAuthType != nil {
		updates.SSHAuthType = *input.SSHAuthType
	}
	key, err := base64.StdEncoding.DecodeString(conf.Encryptkey)
	password, err := common.Encrypt(key, input.SSHPassword)
	if err != nil {
		fmt.Println(err)
	}
	updates.SSHPassword = password

	if input.Region != nil {
		updates.Region = *input.Region
	}

	if input.Tags != nil {
		updates.Tags = strings.Join(input.Tags, ",")
	}

	host, err := models.HostUpdate(id, updates)
	if err != nil {
		return nil, err
	}
	// 异步执行SSH连接测试和信息收集
	//go collectHostInfo(host)

	return host, nil
}

// 收集主机信息
func CollectHostInfo(host *models.Host) {
	//sshClient, err := s.createSSHClient(host)
	//if err != nil {
	//	s.updateHostStatus(host.ID, models.HostStatusOffline)
	//	return
	//}
	//defer sshClient.Close()
	//
	//// 更新主机状态为在线
	//s.updateHostStatus(host.ID, models.HostStatusOnline)
	//
	//// 收集系统信息
	//info, err := s.collectSystemInfo(sshClient)
	//if err != nil {
	//	return
	//}
	//
	//// 更新主机信息
	//updates := map[string]interface{}{
	//	"cpu":           info.CPU,
	//	"memory":        info.Memory,
	//	"diskSize":      info.DiskSize,
	//	"osVersion":     info.OSVersion,
	//	"kernelVersion": info.KernelVersion,
	//	"lastCheckTime": time.Now(),
	//}
	//s.model.Update(host.ID, updates)
}

// 导入主机
func HostsImport(reader io.Reader) error {
	csvReader := csv.NewReader(reader)
	// 跳过标题行
	_, err := csvReader.Read()
	if err != nil {
		return err
	}

	var hosts []*models.Host
	for {
		record, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		// 解析CSV数据
		groupID, _ := strconv.ParseUint(record[0], 10, 32)
		cpu, _ := strconv.Atoi(record[4])
		memory, _ := strconv.Atoi(record[5])
		diskSize, _ := strconv.Atoi(record[6])

		host := &models.Host{
			HostGroupID: uint(groupID),
			Hostname:    record[1],
			PrivateIP:   record[2],
			PublicIP:    record[3],
			CPU:         cpu,
			Memory:      memory,
			DiskSize:    diskSize,
			OSType:      record[7],
			OSVersion:   record[8],
			Description: record[9],
			Source:      models.HostSourceManual,
			Status:      models.HostStatusUnknown,
		}
		hosts = append(hosts, host)
	}

	return models.HostBatchCreate(hosts)
}

// 同步云主机
func SyncCloudHosts(provider string, config map[string]string) error {
	// 实现云主机同步逻辑
	// 这里需要根据不同的云服务商实现具体的同步逻辑
	switch provider {
	case "aliyun":
		return syncAliyunHosts(config)
	case "aws":
		return syncAWSHosts(config)
	default:
		return errors.New("unsupported cloud provider")
	}
}

// 查询主机列表
func HostsList(input *ListHostInput) ([]models.Host, int64, error) {
	params := map[string]interface{}{
		"hostGroupId": input.HostGroupID,
		"keyword":     input.Keyword,
		"status":      input.Status,
	}

	offset := (input.Page - 1) * input.PageSize
	return models.HostsList(params, offset, input.PageSize)
}

// 删除主机
func HostDelete(id uint) error {
	return models.HostDelete(id)
}

// 批量删除主机
func HostBatchDelete(ids []uint) error {
	return models.HostBatchDelete(ids)
}

// 同步阿里云主机
func syncAliyunHosts(config map[string]string) error {
	// 实现阿里云主机同步逻辑
	return nil
}

// 同步AWS主机
func syncAWSHosts(config map[string]string) error {
	// 实现AWS主机同步逻辑
	return nil
}

func GetImportTemplate() (*bytes.Buffer, error) {
	// 创建Excel文件
	f := excelize.NewFile()
	defer func() {
		if err := f.Close(); err != nil {
			log.Println("关闭文件错误:", err)
		}
	}()

	// 设置表头
	headers := []string{
		"主机组", "主机名", "私有IP", "公网IP", "SSH端口",
		"SSH用户名", "认证方式", "SSH密码/密钥", "操作系统类型",
		"操作系统版本", "标签(逗号分隔)", "描述",
	}

	// 在第一个工作表上设置数据
	for i, header := range headers {
		cell := fmt.Sprintf("%c1", 'A'+i)
		f.SetCellValue("Sheet1", cell, header)
	}

	// 设置示例数据
	exampleData := []string{
		"默认分组", "web-server-01", "192.168.1.100", "8.8.8.8", "22",
		"root", "password", "password123", "CentOS",
		"7.9", "web,prod", "Web服务器",
	}

	for i, value := range exampleData {
		cell := fmt.Sprintf("%c2", 'A'+i)
		f.SetCellValue("Sheet1", cell, value)
	}

	// 设置列宽
	for i := 0; i < len(headers); i++ {
		col := fmt.Sprintf("%c", 'A'+i)
		f.SetColWidth("Sheet1", col, col, 15)
	}

	// 准备错误和标题信息的指针
	errorStyle := "stop"
	errorTitle := "输入错误"
	errorMessage := "请选择 password 或 key"

	// 设置数据验证（认证方式的下拉列表）
	dataValidation := excelize.DataValidation{
		AllowBlank:       true,
		Error:            &errorMessage,
		ErrorStyle:       &errorStyle,
		ErrorTitle:       &errorTitle,
		ShowDropDown:     true,
		ShowErrorMessage: true,
		Type:             "list",
		Formula1:         "\"password,key\"",
		Sqref:            "G2:G1000", // 注意这里直接设置范围
	}

	// 设置验证范围
	err := f.AddDataValidation("Sheet1", &dataValidation)
	if err != nil {
		return nil, fmt.Errorf("添加数据验证失败: %v", err)
	}

	// 将文件写入缓冲区
	buffer := new(bytes.Buffer)
	err = f.Write(buffer)
	if err != nil {
		return nil, fmt.Errorf("写入文件失败: %v", err)
	}

	return buffer, nil
}
