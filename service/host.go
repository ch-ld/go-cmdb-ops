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
	"github.com/axgle/mahonia"
	"github.com/xuri/excelize/v2"
	"io"
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

// HostsImport 处理文件导入
func HostsImport(reader io.Reader, filename string) error {
	// 根据文件扩展名选择不同的处理方式
	ext := strings.ToLower(filename)
	if strings.HasSuffix(ext, ".csv") {
		return processCSV(reader)
	} else if strings.HasSuffix(ext, ".xlsx") || strings.HasSuffix(ext, ".xls") {
		return processExcel(reader)
	}
	return fmt.Errorf("不支持的文件格式")
}

// processCSV 处理 CSV 文件
func processCSV(reader io.Reader) error {
	// 读取文件内容
	content, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("读取文件失败: %v", err)
	}

	// 移除 BOM 标记
	content = bytes.TrimPrefix(content, []byte{0xEF, 0xBB, 0xBF})

	// 使用 GBK 解码器
	decoder := mahonia.NewDecoder("gbk")
	if decoder == nil {
		return fmt.Errorf("创建GBK解码器失败")
	}

	// 转换为 UTF-8
	utf8Str := decoder.ConvertString(string(content))
	return processRecords(csv.NewReader(strings.NewReader(utf8Str)))
}

// processExcel 处理 Excel 文件
func processExcel(reader io.Reader) error {
	// 读取 Excel 文件
	xlsx, err := excelize.OpenReader(reader)
	if err != nil {
		return fmt.Errorf("打开Excel文件失败: %v", err)
	}
	defer xlsx.Close()

	// 获取第一个工作表
	sheets := xlsx.GetSheetList()
	if len(sheets) == 0 {
		return fmt.Errorf("Excel文件没有工作表")
	}

	// 读取所有行
	rows, err := xlsx.GetRows(sheets[0])
	if err != nil {
		return fmt.Errorf("读取Excel数据失败: %v", err)
	}

	return processExcelRows(rows)
}

// processRecords 处理记录（共用的处理逻辑）
func processRecords(reader *csv.Reader) error {
	reader.LazyQuotes = true
	reader.TrimLeadingSpace = true
	reader.FieldsPerRecord = -1

	// 读取表头
	headers, err := reader.Read()
	if err != nil {
		return fmt.Errorf("读取表头失败: %v", err)
	}

	return processDataRows(headers, reader)
}

// processExcelRows 处理 Excel 行数据
func processExcelRows(rows [][]string) error {
	if len(rows) == 0 {
		return fmt.Errorf("Excel文件为空")
	}

	headers := rows[0]
	// 创建一个适配器，使Excel数据符合CSV reader的接口
	rowIndex := 1
	reader := &excelReader{
		rows:    rows,
		current: rowIndex,
	}

	return processDataRows(headers, reader)
}

// excelReader 实现类似CSV reader的接口
type excelReader struct {
	rows    [][]string
	current int
}

func (e *excelReader) Read() ([]string, error) {
	if e.current >= len(e.rows) {
		return nil, io.EOF
	}
	row := e.rows[e.current]
	e.current++
	return row, nil
}

// processDataRows 处理数据行（共用的业务逻辑）
func processDataRows(headers []string, reader interface{ Read() ([]string, error) }) error {
	// 验证表头
	expectedHeaders := []string{
		"主机组", "主机名", "私有IP", "公网IP", "SSH端口",
		"SSH用户名", "认证类型", "密码", "操作系统", "系统版本",
		"标签", "描述",
	}
	if len(headers) != len(expectedHeaders) {
		fmt.Println("表格格式不正确，请使用正确的导入模板")
	}

	var hosts []*models.Host
	lineNum := 1

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("第 %d 行数据解析失败: %v", lineNum, err)
		}

		// 验证必填字段
		if len(record) < 3 || record[0] == "" || record[1] == "" || record[2] == "" {
			return fmt.Errorf("第 %d 行数据不完整，主机组、主机名和私有IP为必填项", lineNum)
		}

		// 处理主机组
		host, err := processHostRecord(record, lineNum)
		if err != nil {
			return err
		}
		hosts = append(hosts, host)
		lineNum++
	}

	if len(hosts) == 0 {
		return fmt.Errorf("文件中没有有效的主机数据")
	}

	// 批量创建主机
	return models.HostBatchCreate(hosts)
}

// processHostRecord 处理单条主机记录
func processHostRecord(record []string, lineNum int) (*models.Host, error) {
	if len(record) < 12 {
		return nil, fmt.Errorf("第 %d 行数据字段不足", lineNum)
	}

	// 处理主机组
	groupName := strings.TrimSpace(record[0])
	if groupName == "" {
		return nil, fmt.Errorf("第 %d 行主机组名称不能为空", lineNum)
	}

	groupId, err := models.GetByName(groupName)
	if err != nil {
		hostGroup := &models.HostGroup{
			Name: groupName,
		}
		err := models.Create(hostGroup)
		if err != nil {
			return nil, fmt.Errorf("创建主机组失败: %v", err)
		}
		groupId = hostGroup.ID
	}

	// 处理主机名
	hostname := strings.TrimSpace(record[1])
	if hostname == "" {
		return nil, fmt.Errorf("第 %d 行主机名不能为空", lineNum)
	}

	// 处理私有IP
	privateIP := strings.TrimSpace(record[2])
	if privateIP == "" {
		return nil, fmt.Errorf("第 %d 行私有IP不能为空", lineNum)
	}

	// 处理 SSH 端口
	sshPort := 22
	if record[4] != "" {
		port, err := strconv.Atoi(strings.TrimSpace(record[4]))
		if err != nil {
			return nil, fmt.Errorf("第 %d 行 SSH 端口格式错误", lineNum)
		}
		if port <= 0 || port > 65535 {
			return nil, fmt.Errorf("第 %d 行 SSH 端口范围无效（1-65535）", lineNum)
		}
		sshPort = port
	}

	// 处理密码加密
	var password string
	if record[7] != "" {
		key, err := base64.StdEncoding.DecodeString(conf.Encryptkey)
		if err != nil {
			return nil, fmt.Errorf("加密密钥解析失败: %v", err)
		}
		password, err = common.Encrypt(key, strings.TrimSpace(record[7]))
		if err != nil {
			return nil, fmt.Errorf("密码加密失败: %v", err)
		}
	}

	// 验证认证类型
	authType := strings.TrimSpace(record[6])
	if authType != "" && !isValidAuthType(authType) {
		return nil, fmt.Errorf("第 %d 行认证类型无效", lineNum)
	}

	// 创建主机记录
	host := &models.Host{
		HostGroupID: groupId,
		Hostname:    hostname,
		PrivateIP:   privateIP,
		PublicIP:    strings.TrimSpace(record[3]),
		SSHPort:     sshPort,
		SSHUser:     strings.TrimSpace(record[5]),
		SSHAuthType: models.SSHAuthType(authType),
		SSHPassword: password,
		OSType:      strings.TrimSpace(record[8]),
		OSVersion:   strings.TrimSpace(record[9]),
		Tags:        strings.TrimSpace(record[10]),
		Description: strings.TrimSpace(record[11]),
		Source:      models.HostSourceImport,
		Status:      models.HostStatusUnknown,
	}

	// 验证主机记录的完整性
	if err := models.ValidateHost(host, lineNum); err != nil {
		return nil, err
	}

	return host, nil
}

// validateHost 验证主机记录的完整性

// isValidAuthType 验证认证类型是否有效
func isValidAuthType(authType string) bool {
	validTypes := []string{"password", "key"} // 根据实际情况修改
	for _, t := range validTypes {
		if authType == t {
			return true
		}
	}
	return false
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

// 前端实现
//func GetImportTemplate() (*bytes.Buffer, error) {
//	// 创建Excel文件
//	f := excelize.NewFile()
//	defer func() {
//		if err := f.Close(); err != nil {
//			log.Println("关闭文件错误:", err)
//		}
//	}()
//
//	// 设置表头
//	headers := []string{
//		"主机组", "主机名", "私有IP", "公网IP", "SSH端口",
//		"SSH用户名", "认证方式", "SSH密码/密钥", "操作系统类型",
//		"操作系统版本", "标签(逗号分隔)", "描述",
//	}
//
//	// 在第一个工作表上设置数据
//	for i, header := range headers {
//		cell := fmt.Sprintf("%c1", 'A'+i)
//		f.SetCellValue("Sheet1", cell, header)
//	}
//
//	// 设置示例数据
//	exampleData := []string{
//		"默认分组", "web-server-01", "192.168.1.100", "8.8.8.8", "22",
//		"root", "password", "password123", "CentOS",
//		"7.9", "web,prod", "Web服务器",
//	}
//
//	for i, value := range exampleData {
//		cell := fmt.Sprintf("%c2", 'A'+i)
//		f.SetCellValue("Sheet1", cell, value)
//	}
//
//	// 设置列宽
//	for i := 0; i < len(headers); i++ {
//		col := fmt.Sprintf("%c", 'A'+i)
//		f.SetColWidth("Sheet1", col, col, 15)
//	}
//
//	// 准备错误和标题信息的指针
//	errorStyle := "stop"
//	errorTitle := "输入错误"
//	errorMessage := "请选择 password 或 key"
//
//	// 设置数据验证（认证方式的下拉列表）
//	dataValidation := excelize.DataValidation{
//		AllowBlank:       true,
//		Error:            &errorMessage,
//		ErrorStyle:       &errorStyle,
//		ErrorTitle:       &errorTitle,
//		ShowDropDown:     true,
//		ShowErrorMessage: true,
//		Type:             "list",
//		Formula1:         "\"password,key\"",
//		Sqref:            "G2:G1000", // 注意这里直接设置范围
//	}
//
//	// 设置验证范围
//	err := f.AddDataValidation("Sheet1", &dataValidation)
//	if err != nil {
//		return nil, fmt.Errorf("添加数据验证失败: %v", err)
//	}
//
//	// 将文件写入缓冲区
//	buffer := new(bytes.Buffer)
//	err = f.Write(buffer)
//	if err != nil {
//		return nil, fmt.Errorf("写入文件失败: %v", err)
//	}
//
//	return buffer, nil
//}
