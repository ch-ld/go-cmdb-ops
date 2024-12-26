package models

import (
	"github.com/jinzhu/gorm"
	"time"
)

type HostStatus string
type HostSource string
type SSHAuthType string

const (
	HostStatusOnline  HostStatus = "online"
	HostStatusOffline HostStatus = "offline"
	HostStatusUnknown HostStatus = "unknown"

	HostSourceManual HostSource = "manual"
	HostSourceImport HostSource = "import"
	HostSourceAliyun HostSource = "aliyun"
	HostSourceAWS    HostSource = "aws"

	SSHAuthPassword SSHAuthType = "password"
	SSHAuthKey      SSHAuthType = "key"
)

type Host struct {
	ID          uint        `gorm:"primarykey" json:"id"`
	HostGroupID uint        `gorm:"not null;index" json:"hostGroupId"`
	Hostname    string      `gorm:"type:varchar(100);not null" json:"hostname"`
	PrivateIP   string      `gorm:"type:varchar(15)" json:"privateIp"`
	PublicIP    string      `gorm:"type:varchar(15)" json:"publicIp"`
	SSHPort     int         `gorm:"default:22" json:"sshPort"`
	SSHUser     string      `gorm:"type:varchar(50)" json:"sshUser"`
	SSHAuthType SSHAuthType `gorm:"type:varchar(20);default:'password'" json:"sshAuthType"`
	//SSHPassword     string      `gorm:"type:varchar(255)" json:"-"` // 不返回密码
	//SSHKey          string      `gorm:"type:text" json:"-"`         // 不返回密钥
	SSHPassword     string     `gorm:"type:varchar(255)" json:"sshPassword"`
	SSHKey          string     `gorm:"type:text" json:"sshKey"`
	CPU             int        `gorm:"comment:'CPU核心数'" json:"cpu"`
	CPUUsage        float64    `gorm:"comment:'CPU使用率'" json:"cpuUsage"`
	Memory          int        `gorm:"comment:'内存大小(GB)'" json:"memory"`
	MemoryUsage     float64    `gorm:"comment:'内存使用率'" json:"memoryUsage"`
	DiskSize        int        `gorm:"comment:'磁盘大小(GB)'" json:"diskSize"`
	DiskUsage       float64    `gorm:"comment:'磁盘使用率'" json:"diskUsage"`
	OSType          string     `gorm:"type:varchar(50)" json:"osType"`
	OSVersion       string     `gorm:"type:varchar(50)" json:"osVersion"`
	KernelVersion   string     `gorm:"type:varchar(50)" json:"kernelVersion"`
	Status          HostStatus `gorm:"type:varchar(20);default:'unknown'" json:"status"`
	Source          HostSource `gorm:"type:varchar(20);not null" json:"source"`
	CloudInstanceID string     `gorm:"type:varchar(100)" json:"cloudInstanceId"`
	Region          string     `gorm:"type:varchar(50)" json:"region"`
	Tags            string     `gorm:"type:text" json:"tags"`
	Description     string     `gorm:"type:varchar(255)" json:"description"`
	LastCheckTime   *time.Time `json:"lastCheckTime"`
	CreatedAt       time.Time  `json:"createdAt"`
	UpdatedAt       time.Time  `json:"updatedAt"`
	HostGroup       HostGroup  `gorm:"foreignKey:HostGroupID" json:"hostGroup"`
}

// 创建主机
func HostCreate(host *Host) error {
	return db.Transaction(func(tx *gorm.DB) error {
		// 1. 创建主机
		if err := tx.Create(host).Error; err != nil {
			return err
		}
		// 2. 更新主机组计数
		if err := tx.Model(&HostGroup{}).
			Where("id = ?", host.HostGroupID).
			Update("host_count", gorm.Expr("host_count + 1")).Error; err != nil {
			return err
		}
		return nil
	})
}

// 批量创建主机
func HostBatchCreate(hosts []*Host) error {
	return db.Transaction(func(tx *gorm.DB) error {
		// 1. 批量创建主机
		if err := tx.Create(hosts).Error; err != nil {
			return err
		}
		// 2. 统计并更新每个主机组的计数
		groupCounts := make(map[uint]int64)
		for _, host := range hosts {
			groupCounts[host.HostGroupID]++
		}
		// 3. 更新主机组计数
		for groupID, count := range groupCounts {
			if err := tx.Model(&HostGroup{}).
				Where("id = ?", groupID).
				Update("host_count", gorm.Expr("host_count + ?", count)).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// 查询主机列表
func HostsList(params map[string]interface{}, offset, limit int) ([]Host, int64, error) {
	var hosts []Host
	var total int64

	query := db.Model(&Host{}).Preload("HostGroup")

	// 条件查询
	if groupID, ok := params["hostGroupId"].(uint); ok && groupID > 0 {
		query = query.Where("host_group_id = ?", groupID)
	}

	if keyword, ok := params["keyword"].(string); ok && keyword != "" {
		query = query.Where("hostname LIKE ? OR private_ip LIKE ? OR public_ip LIKE ?",
			"%"+keyword+"%", "%"+keyword+"%", "%"+keyword+"%")
	}

	if status, ok := params["status"].(string); ok && status != "" {
		query = query.Where("status = ?", status)
	}

	err := query.Count(&total).Error
	if err != nil {
		return nil, 0, err
	}

	err = query.Offset(offset).Limit(limit).Find(&hosts).Error
	return hosts, total, err
}

// 根据主机ID查询主机
func HostGetByID(id uint) (*Host, error) {
	var host Host
	if err := db.Preload("HostGroup").First(&host, id).Error; err != nil {
		return nil, err
	}
	return &host, nil
}

// 更新主机信息
func HostUpdate(id string, updates Host) (*Host, error) {
	var host Host
	if err := db.First(&host, id).Error; err != nil {
		return nil, err
	}

	if err := db.Model(&host).Updates(updates).Error; err != nil {
		return nil, err
	}

	return &host, nil
}

// 删除主机
func HostDelete(id uint) error {
	// 开启事务
	return db.Transaction(func(tx *gorm.DB) error {
		// 1. 先查询主机，获取HostGroupID
		var host Host
		if err := tx.First(&host, id).Error; err != nil {
			return err
		}
		// 记录HostGroupID
		hostGroupID := host.HostGroupID
		// 2. 删除主机
		if err := tx.Delete(&host).Error; err != nil {
			return err
		}

		// 3. 查询该主机组剩余主机数量
		var count int64
		err := tx.Model(&Host{}).Where("host_group_id = ?", hostGroupID).Count(&count).Error
		if err != nil {
			return err
		}

		// 4. 更新主机组的host_count
		return tx.Model(&HostGroup{}).
			Where("id = ?", hostGroupID).
			Update("host_count", count).Error
	})
}

// 批量删除主机
func HostBatchDelete(ids []uint) error {
	return db.Transaction(func(tx *gorm.DB) error {
		// 1. 查询要删除的主机，获取涉及的主机组
		var hosts []Host
		if err := tx.Find(&hosts, ids).Error; err != nil {
			return err
		}

		// 2. 获取涉及的主机组ID
		groupIDs := make(map[uint]bool)
		for _, host := range hosts {
			groupIDs[host.HostGroupID] = true
		}

		// 3. 删除主机
		if err := tx.Delete(&Host{}, ids).Error; err != nil {
			return err
		}

		// 4. 更新每个受影响的主机组计数
		for groupID := range groupIDs {
			var count int64
			err := tx.Model(&Host{}).Where("host_group_id = ?", groupID).Count(&count).Error
			if err != nil {
				return err
			}

			if err := tx.Model(&HostGroup{}).
				Where("id = ?", groupID).
				Update("host_count", count).Error; err != nil {
				return err
			}
		}

		return nil
	})
}
