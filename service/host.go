package service

import (
	"bytes"
	"cmdb-ops-flow/conf"
	"cmdb-ops-flow/models"
	"cmdb-ops-flow/utils/common"
	"cmdb-ops-flow/utils/ssh"
	"context"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ecs"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	// AWS SDK v2 包
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/axgle/mahonia"
	"github.com/xuri/excelize/v2"
	"io"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"
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
func HostUpdate(id uint, input UpdateHostInput) (*models.Host, error) {

	// 构建更新数据
	updates := &models.Host{}
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
func CollectHostInfo(hostId uint) error {
	host, _ := models.HostGetByID(hostId)
	key, err := base64.StdEncoding.DecodeString(conf.Encryptkey)
	password, err := common.Decrypt(key, host.SSHPassword)
	if err != nil {
		fmt.Println("解密失败:", err)
		return err
	}
	config := &ssh.SSHClientConfig{
		Timeout:   time.Second * 5,
		IP:        host.PrivateIP,
		Port:      host.SSHPort,
		UserName:  host.SSHUser,
		Password:  password,
		AuthModel: "PASSWORD",
	}

	//// 获取主机信息
	//cpu, err := ssh.SshCommand(config, "nproc")
	//if err != nil {
	//	return err
	//}
	//cpuInt, err := strconv.Atoi(strings.TrimSpace(cpu))
	//if err != nil {
	//	return fmt.Errorf("cpu转换失败: %v", err)
	//}
	//cpuUsage, err := ssh.SshCommand(config, "top -bn1 | grep 'Cpu(s)' | sed 's/.*, *\\([0-9.]*\\)%* id.*/\\1/' | awk '{print 100 - $1}'")
	//if err != nil {
	//	return err
	//}
	//cpuUsageFloat, err := strconv.ParseFloat(strings.TrimSpace(cpuUsage), 64)
	//if err != nil {
	//	return fmt.Errorf("cpuUsage转换失败: %v", err)
	//}
	//memory, err := ssh.SshCommand(config, "free -m | awk 'NR==2{printf  $2}'")
	//if err != nil {
	//	return err
	//}
	//memoryInt, err := strconv.Atoi(strings.TrimSpace(memory))
	//if err != nil {
	//	return fmt.Errorf("memory转换失败: %v", err)
	//}
	//memoryUsage, err := ssh.SshCommand(config, "free | grep Mem | awk '{print $3/$2 * 100.0}'")
	//if err != nil {
	//	return err
	//}
	//memoryUsageFloat, err := strconv.ParseFloat(strings.TrimSpace(memoryUsage), 64)
	//if err != nil {
	//	return fmt.Errorf("memoryUsage转换失败: %v", err)
	//}
	//diskSize, err := ssh.SshCommand(config, "df -h | grep '^/dev/' | awk '{print $2}' | head -n 1 | awk -F 'G' '{print $1}'")
	//if err != nil {
	//	return err
	//}
	//diskSizeInt, err := strconv.Atoi(strings.TrimSpace(diskSize))
	//if err != nil {
	//	return fmt.Errorf("diskSize转换失败: %v", err)
	//}
	//diskUsage, err := ssh.SshCommand(config, "df -h | grep '^/dev/' | awk '{print $3}' | head -n 1| awk -F 'G' '{print $1}'")
	//if err != nil {
	//	return err
	//}
	//diskUsageFloat, err := strconv.ParseFloat(strings.TrimSpace(diskUsage), 64)
	//if err != nil {
	//	return fmt.Errorf("diskUsage转换失败: %v", err)
	//}
	//osType, err := ssh.SshCommand(config, "uname -o | awk -F '/' '{print $NF}'")
	//if err != nil {
	//	return err
	//}
	//osVersion, err := ssh.SshCommand(config, "lsb_release -d | cut -f2")
	//if err != nil {
	//	return err
	//}
	//kernelVersion, err := ssh.SshCommand(config, "uname -r")
	//if err != nil {
	//	return err
	//}
	//
	//updates := models.Host{
	//	ID:            hostId,
	//	CPU:           cpuInt,
	//	CPUUsage:      cpuUsageFloat,
	//	Memory:        memoryInt,
	//	MemoryUsage:   memoryUsageFloat,
	//	DiskSize:      diskSizeInt,
	//	DiskUsage:     diskUsageFloat,
	//	OSType:        strings.TrimSpace(osType),
	//	OSVersion:     strings.TrimSpace(osVersion),
	//	KernelVersion: strings.TrimSpace(kernelVersion),
	//	Status:        models.HostStatusOnline,
	//	LastCheckTime: time.Now(),
	//}

	// 获取主机信息(优化版)
	// 定义一个结构体来存储结果
	type MetricResult struct {
		Value interface{}
		Err   error
	}
	// 创建通道来接收结果
	results := make(map[string]chan MetricResult)
	metrics := []string{"cpu", "cpuUsage", "memory", "memoryUsage", "disk", "os"}
	for _, metric := range metrics {
		results[metric] = make(chan MetricResult, 1)
	}

	// CPU 和负载信息
	go func() {
		cmd := `nproc && top -bn1 | grep 'Cpu(s)' | sed 's/.*, *\\([0-9.]*\\)%* id.*/\\1/' | awk '{print 100 -$1}'`
		output, err := ssh.SshCommand(config, cmd)
		if err != nil {
			results["cpu"] <- MetricResult{nil, err}
			results["cpuUsage"] <- MetricResult{nil, err}
			return
		}

		lines := strings.Split(strings.TrimSpace(output), "\n")
		if len(lines) >= 2 {
			cpu, err := strconv.Atoi(lines[0])
			results["cpu"] <- MetricResult{cpu, err}

			cpuUsage, err := strconv.ParseFloat(lines[1], 64)
			results["cpuUsage"] <- MetricResult{cpuUsage, err}
		}
	}()

	// 内存信息
	go func() {
		cmd := `free -m | awk 'NR==2{printf "%s %s", $2, $3/$2 * 100}'`
		output, err := ssh.SshCommand(config, cmd)
		if err != nil {
			results["memory"] <- MetricResult{nil, err}
			results["memoryUsage"] <- MetricResult{nil, err}
			return
		}

		parts := strings.Fields(output)
		if len(parts) >= 2 {
			memory, err := strconv.Atoi(parts[0])
			results["memory"] <- MetricResult{memory, err}

			memoryUsage, err := strconv.ParseFloat(parts[1], 64)
			results["memoryUsage"] <- MetricResult{memoryUsage, err}
		}
	}()

	// 磁盘信息
	go func() {
		cmd := `df / | awk 'NR==2{printf "%d %.2f", $2/1024/1024, $3/$2 * 100}'`
		output, err := ssh.SshCommand(config, cmd)
		if err != nil {
			results["disk"] <- MetricResult{nil, err}
			return
		}

		var diskSize int
		var diskUsage float64
		_, err = fmt.Sscanf(output, "%d %f", &diskSize, &diskUsage)
		results["disk"] <- MetricResult{struct {
			size  int
			usage float64
		}{diskSize, diskUsage}, err}
	}()

	// 操作系统信息
	go func() {
		cmd := `echo "$(uname -o | awk -F '/' '{print $NF}')|||$(lsb_release -d | cut -f2)|||$(uname -r)"`
		output, err := ssh.SshCommand(config, cmd)
		if err != nil {
			results["os"] <- MetricResult{nil, err}
			return
		}

		parts := strings.Split(strings.TrimSpace(output), "|||")
		if len(parts) >= 3 {
			results["os"] <- MetricResult{parts, nil}
		}
	}()

	// 收集结果
	updates := &models.Host{}
	updates.ID = hostId
	updates.Status = models.HostStatusOnline
	updates.LastCheckTime = time.Now()

	// 等待所有结果
	for metric, ch := range results {
		result := <-ch
		if result.Err != nil {
			return fmt.Errorf("获取%s信息失败: %v", metric, result.Err)
		}

		switch metric {
		case "cpu":
			updates.CPU = result.Value.(int)
		case "cpuUsage":
			updates.CPUUsage = result.Value.(float64)
		case "memory":
			updates.Memory = result.Value.(int)
		case "memoryUsage":
			updates.MemoryUsage = result.Value.(float64)
		case "disk":
			disk := result.Value.(struct {
				size  int
				usage float64
			})
			updates.DiskSize = disk.size
			updates.DiskUsage = disk.usage
		case "os":
			osInfo := result.Value.([]string)
			updates.OSType = osInfo[0]
			updates.OSVersion = osInfo[1]
			updates.KernelVersion = osInfo[2]
		}
	}

	// 更新数据库
	host, err = models.HostUpdate(hostId, updates)
	if err != nil {
		return fmt.Errorf("更新主机信息失败: %v", err)
	}

	return nil
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

// 同步云主机
func SyncCloudHosts(provider string, config map[string]string, hostGroupId int) error {
	regions := strings.Split(config["regions"], ",")
	var wg sync.WaitGroup
	errChan := make(chan error, len(regions))
	for _, region := range regions {
		wg.Add(1)
		go func(region string) {
			defer wg.Done()
			var err error
			switch provider {
			case "aliyun":
				err = syncAliyunHosts(config["accessKey"], config["accessSecret"], region, hostGroupId)
			case "aws":
				err = syncAWSHosts(config["accessKey"], config["accessSecret"], region, hostGroupId)
			}
			if err != nil {
				errChan <- fmt.Errorf("region %s sync failed: %v", region, err)
			}
		}(region)
	}
	// 等待所有同步完成
	wg.Wait()
	close(errChan)
	// 收集错误
	var errors []string
	for err := range errChan {
		errors = append(errors, err.Error())
	}
	if len(errors) > 0 {
		return fmt.Errorf("同步出现错误: %s", strings.Join(errors, "; "))
	}
	return nil
}

// 同步阿里云主机
func syncAliyunHosts(accessKey, accessSecret, region string, hostGroupId int) error {
	if accessKey == "" || accessSecret == "" || region == "" {
		return fmt.Errorf("参数不能为空: accessKey, accessSecret, region")
	}

	client, err := ecs.NewClientWithAccessKey(region, accessKey, accessSecret)
	if err != nil {
		return fmt.Errorf("创建阿里云客户端失败: %v", err)
	}

	request := ecs.CreateDescribeInstancesRequest()
	request.RegionId = region
	// 设置较大的页面大小以获取所有实例
	request.PageSize = requests.NewInteger(100)

	response, err := client.DescribeInstances(request)
	if err != nil {
		return fmt.Errorf("获取实例列表失败: %v", err)
	}

	if response == nil || len(response.Instances.Instance) == 0 {
		return fmt.Errorf("未找到任何实例")
	}

	for _, instance := range response.Instances.Instance {
		// 获取私网IP
		var privateIP string
		if len(instance.VpcAttributes.PrivateIpAddress.IpAddress) > 0 {
			privateIP = instance.VpcAttributes.PrivateIpAddress.IpAddress[0]
		}

		// 获取公网IP (优先获取弹性公网IP)
		var publicIP string
		if instance.EipAddress.IpAddress != "" {
			publicIP = instance.EipAddress.IpAddress
		} else if len(instance.PublicIpAddress.IpAddress) > 0 {
			publicIP = instance.PublicIpAddress.IpAddress[0]
		}

		// 检查必要字段
		if instance.InstanceName == "" {
			instance.InstanceName = instance.InstanceId // 如果实例名为空，使用实例ID
		}

		// 处理操作系统信息
		osType := instance.OSType
		if osType == "" {
			osType = "Unknown"
		}
		osVersion := instance.OSName
		if osVersion == "" {
			osVersion = "Unknown"
		}

		host := &models.Host{
			Hostname:        instance.InstanceName,
			HostGroupID:     uint(hostGroupId),
			PrivateIP:       privateIP,
			PublicIP:        publicIP,
			CPU:             instance.Cpu,
			Memory:          instance.Memory,
			OSType:          osType,
			OSVersion:       osVersion,
			Status:          convertAliyunStatus(instance.Status),
			Source:          models.HostSourceAliyun,
			CloudInstanceID: instance.InstanceId,
			Region:          region,
			Tags:            convertAliyunTags(instance.Tags.Tag),
			LastCheckTime:   time.Now(),
		}

		// 检查必要字段是否为空
		if err := validateHost(host); err != nil {
			log.Printf("警告: 实例 %s 数据验证失败: %v", instance.InstanceId, err)
			continue // 跳过此实例，继续处理下一个
		}

		// 尝试创建或更新主机记录
		HostExists, HostId := models.IsHostnameExists(host.Hostname)
		if HostExists {
			host.ID = HostId
			err, _ := models.HostUpdate(HostId, host)
			if err != nil {
				log.Printf("警告: 更新实例 %s 失败: %v", instance.InstanceId, err)
				continue
			}
		} else {
			err := models.HostCreate(host)
			if err != nil {
				log.Printf("警告: 保存实例 %s 失败: %v", instance.InstanceId, err)
				continue
			}
		}
	}
	return nil
}

// 同步AWS主机
func syncAWSHosts(accessKey, accessSecret, region string, hostGroupId int) error {
	if accessKey == "" || accessSecret == "" || region == "" {
		return fmt.Errorf("参数不能为空: accessKey, accessSecret, region")
	}

	// 创建AWS配置
	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion(region),
		config.WithCredentialsProvider(aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(
			accessKey, accessSecret, "",
		))),
	)
	if err != nil {
		return fmt.Errorf("配置AWS客户端失败: %v", err)
	}

	// 创建EC2客户端
	client := ec2.NewFromConfig(cfg)
	input := &ec2.DescribeInstancesInput{}

	// 获取实例列表
	result, err := client.DescribeInstances(context.Background(), input)
	if err != nil {
		return fmt.Errorf("获取AWS实例列表失败: %v", err)
	}

	for _, reservation := range result.Reservations {
		for _, instance := range reservation.Instances {
			// 检查必要字段
			if instance.InstanceId == nil {
				continue
			}

			// 获取私网IP
			privateIP := ""
			if instance.PrivateIpAddress != nil {
				privateIP = *instance.PrivateIpAddress
			}

			// 获取公网IP
			publicIP := ""
			if instance.PublicIpAddress != nil {
				publicIP = *instance.PublicIpAddress
			}

			// 获取主机名
			hostname := getAWSTagValue(instance.Tags, "Name")
			if hostname == "" {
				hostname = *instance.InstanceId
			}

			//// 获取CPU核心数
			//cpuCount := 1
			//if instance.CpuOptions != nil && instance.CpuOptions.CoreCount != nil {
			//	cpuCount = int(*instance.CpuOptions.CoreCount)
			//}

			host := &models.Host{
				Hostname:    hostname,
				HostGroupID: uint(hostGroupId),
				PrivateIP:   privateIP,
				PublicIP:    publicIP,
				CPU:         awsInstanceCPUMemory[string(instance.InstanceType)].CPU,
				Memory:      awsInstanceCPUMemory[string(instance.InstanceType)].Memory * 1024,
				//OSType:          determineAWSOSType(instance),
				OSVersion:       aws.ToString(instance.PlatformDetails),
				Status:          convertAWSStatus(instance.State.Name),
				Source:          models.HostSourceAWS,
				CloudInstanceID: *instance.InstanceId,
				Region:          region,
				Tags:            convertAWSTags(instance.Tags),
				LastCheckTime:   time.Now(),
			}

			// 验证主机信息
			if err := validateAWSHost(host); err != nil {
				continue
			}
			// 尝试创建或更新主机记录
			HostExists, HostId := models.IsHostnameExists(host.Hostname)
			if HostExists {
				host.ID = HostId
				err, _ := models.HostUpdate(HostId, host)
				if err != nil {
					log.Printf("警告: 更新实例 %s 失败: %v", instance.InstanceId, err)
					continue
				}
			} else {
				err := models.HostCreate(host)
				if err != nil {
					log.Printf("警告: 保存实例 %s 失败: %v", instance.InstanceId, err)
					continue
				}
			}
		}
	}

	return nil
}

// 验证主机信息是否完整
func validateHost(host *models.Host) error {
	if host.CloudInstanceID == "" {
		return fmt.Errorf("云实例ID不能为空")
	}
	if host.Hostname == "" {
		return fmt.Errorf("主机名不能为空")
	}
	if host.PrivateIP == "" {
		return fmt.Errorf("私网IP不能为空")
	}
	if host.CPU <= 0 {
		return fmt.Errorf("CPU核数必须大于0")
	}
	if host.Memory <= 0 {
		return fmt.Errorf("内存大小必须大于0")
	}
	return nil
}

func convertAliyunTags(tags []ecs.Tag) string {
	var tagPairs []string
	for _, tag := range tags {
		tagPairs = append(tagPairs, fmt.Sprintf("%s=%s", tag.TagKey, tag.TagValue))
	}
	return strings.Join(tagPairs, ",")
}

// 辅助函数
func convertAliyunStatus(status string) models.HostStatus {
	switch status {
	case "Running":
		return models.HostStatusOnline
	case "Stopped":
		return models.HostStatusOffline
	default:
		return models.HostStatusUnknown
	}
}

// AWS实例CPU和内存映射表（根据实例类型）
var awsInstanceCPUMemory = map[string]struct {
	CPU    int
	Memory int
}{
	"t2.nano":       {CPU: 1, Memory: 1},
	"t2.micro":      {CPU: 1, Memory: 1},
	"t2.small":      {CPU: 1, Memory: 2},
	"t2.medium":     {CPU: 2, Memory: 4},
	"t2.large":      {CPU: 2, Memory: 8},
	"t2.xlarge":     {CPU: 4, Memory: 16},
	"t2.2xlarge":    {CPU: 8, Memory: 32},
	"t3.nano":       {CPU: 2, Memory: 1},
	"t3.micro":      {CPU: 2, Memory: 1},
	"t3.small":      {CPU: 2, Memory: 2},
	"t3.medium":     {CPU: 2, Memory: 4},
	"t3.large":      {CPU: 2, Memory: 8},
	"t3.xlarge":     {CPU: 4, Memory: 16},
	"t3.2xlarge":    {CPU: 8, Memory: 32},
	"m5.large":      {CPU: 2, Memory: 8},
	"m5.xlarge":     {CPU: 4, Memory: 16},
	"m5.2xlarge":    {CPU: 8, Memory: 32},
	"m5.4xlarge":    {CPU: 16, Memory: 64},
	"m5.8xlarge":    {CPU: 32, Memory: 128},
	"m5.12xlarge":   {CPU: 48, Memory: 192},
	"m5.16xlarge":   {CPU: 64, Memory: 256},
	"m5.24xlarge":   {CPU: 96, Memory: 384},
	"m6g.medium":    {CPU: 1, Memory: 2},
	"m6g.large":     {CPU: 2, Memory: 4},
	"m6g.xlarge":    {CPU: 4, Memory: 8},
	"m6g.2xlarge":   {CPU: 8, Memory: 16},
	"m6g.4xlarge":   {CPU: 16, Memory: 32},
	"m6g.8xlarge":   {CPU: 32, Memory: 64},
	"m6g.12xlarge":  {CPU: 48, Memory: 96},
	"c5.large":      {CPU: 2, Memory: 4},
	"c5.xlarge":     {CPU: 4, Memory: 8},
	"c5.2xlarge":    {CPU: 8, Memory: 16},
	"c5.4xlarge":    {CPU: 16, Memory: 32},
	"c5.9xlarge":    {CPU: 36, Memory: 72},
	"c5.12xlarge":   {CPU: 48, Memory: 96},
	"c5.18xlarge":   {CPU: 72, Memory: 144},
	"c5.24xlarge":   {CPU: 96, Memory: 192},
	"c6g.medium":    {CPU: 1, Memory: 2},
	"c6g.large":     {CPU: 2, Memory: 4},
	"c6g.xlarge":    {CPU: 4, Memory: 8},
	"c6g.2xlarge":   {CPU: 8, Memory: 16},
	"c6g.4xlarge":   {CPU: 16, Memory: 32},
	"c6g.8xlarge":   {CPU: 32, Memory: 64},
	"c6g.12xlarge":  {CPU: 48, Memory: 96},
	"r5.large":      {CPU: 2, Memory: 16},
	"r5.xlarge":     {CPU: 4, Memory: 32},
	"r5.2xlarge":    {CPU: 8, Memory: 64},
	"r5.4xlarge":    {CPU: 16, Memory: 128},
	"r5.8xlarge":    {CPU: 32, Memory: 256},
	"r5.12xlarge":   {CPU: 48, Memory: 384},
	"r5.16xlarge":   {CPU: 64, Memory: 512},
	"r5.24xlarge":   {CPU: 96, Memory: 768},
	"r6g.medium":    {CPU: 1, Memory: 4},
	"r6g.large":     {CPU: 2, Memory: 8},
	"r6g.xlarge":    {CPU: 4, Memory: 16},
	"r6g.2xlarge":   {CPU: 8, Memory: 32},
	"r6g.4xlarge":   {CPU: 16, Memory: 64},
	"r6g.8xlarge":   {CPU: 32, Memory: 128},
	"r6g.12xlarge":  {CPU: 48, Memory: 192},
	"x5.2xlarge":    {CPU: 8, Memory: 64},
	"x5.4xlarge":    {CPU: 16, Memory: 128},
	"x5.8xlarge":    {CPU: 32, Memory: 256},
	"x5.12xlarge":   {CPU: 48, Memory: 384},
	"x5.16xlarge":   {CPU: 64, Memory: 512},
	"x5.24xlarge":   {CPU: 96, Memory: 768},
	"i3.large":      {CPU: 2, Memory: 16},
	"i3.xlarge":     {CPU: 4, Memory: 32},
	"i3.2xlarge":    {CPU: 8, Memory: 61},
	"i3.4xlarge":    {CPU: 16, Memory: 122},
	"i3.8xlarge":    {CPU: 32, Memory: 244},
	"i3.16xlarge":   {CPU: 64, Memory: 488},
	"g4dn.medium":   {CPU: 1, Memory: 8},
	"g4dn.large":    {CPU: 2, Memory: 16},
	"g4dn.xlarge":   {CPU: 4, Memory: 16},
	"g4dn.2xlarge":  {CPU: 8, Memory: 32},
	"g4dn.4xlarge":  {CPU: 16, Memory: 64},
	"g4dn.8xlarge":  {CPU: 32, Memory: 128},
	"g4dn.12xlarge": {CPU: 48, Memory: 192},
	"g4dn.16xlarge": {CPU: 64, Memory: 256},
	"p3.2xlarge":    {CPU: 8, Memory: 61},
	"p3.8xlarge":    {CPU: 32, Memory: 244},
	"p3.16xlarge":   {CPU: 64, Memory: 488},
}

//// 获取AWS实例内存大小
//func getAWSInstanceMemory(instanceType string) int {
//	if memory, ok := awsInstanceCPUMemory[instanceType].Memory; ok {
//		return memory
//	}
//	return 0 // 未知实例类型返回0
//}

// 获取AWS标签值
func getAWSTagValue(tags []types.Tag, key string) string {
	for _, tag := range tags {
		if aws.ToString(tag.Key) == key {
			return aws.ToString(tag.Value)
		}
	}
	return ""
}

// 转换AWS状态到系统状态
func convertAWSStatus(state types.InstanceStateName) models.HostStatus {
	switch state {
	case types.InstanceStateNameRunning:
		return models.HostStatusOnline
	case types.InstanceStateNameStopped:
		return models.HostStatusOffline
	case types.InstanceStateNamePending:
		return models.HostStatusOnline
	case types.InstanceStateNameStopping:
		return models.HostStatusOffline
	default:
		return models.HostStatusUnknown
	}
}

// 转换AWS标签到JSON字符串
func convertAWSTags(tags []types.Tag) string {
	tagsMap := make(map[string]string)
	for _, tag := range tags {
		if tag.Key != nil && tag.Value != nil {
			tagsMap[*tag.Key] = *tag.Value
		}
	}

	jsonBytes, err := json.Marshal(tagsMap)
	if err != nil {
		return "{}"
	}
	return string(jsonBytes)
}

// 验证AWS主机信息
func validateAWSHost(host *models.Host) error {
	if host.CloudInstanceID == "" {
		return fmt.Errorf("云实例ID不能为空")
	}
	if host.Hostname == "" {
		return fmt.Errorf("主机名不能为空")
	}
	if host.PrivateIP == "" {
		return fmt.Errorf("私网IP不能为空")
	}
	return nil
}

//// 确定AWS实例的操作系统类型
//func determineAWSOSType(instance types.Instance) string {
//	if instance.Platform == types.PlatformValuesWindows {
//		return "Windows"
//	}
//	return "Linux"
//}

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
