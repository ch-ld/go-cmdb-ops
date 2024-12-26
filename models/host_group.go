// models/host_group.go
package models

import (
	"time"
)

type HostGroup struct {
	ID          uint      `gorm:"primarykey" json:"id"`
	Name        string    `gorm:"type:varchar(50);not null;uniqueIndex;comment:'主机组名称'" json:"name"`
	Description string    `gorm:"type:varchar(255);comment:'描述'" json:"description"`
	HostCount   int       `gorm:"default:0;comment:'主机数量'" json:"hostCount"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

// 创建主机组
func Create(hostGroup *HostGroup) error {
	return db.Create(hostGroup).Error
}

// 根据条件查询主机组列表
func List(name string, offset, limit int) ([]HostGroup, int64, error) {
	var groups []HostGroup
	var total int64

	query := db.Model(&HostGroup{})
	if name != "" {
		query = query.Where("name LIKE ?", "%"+name+"%")
	}

	err := query.Count(&total).Error
	if err != nil {
		return nil, 0, err
	}

	err = query.Offset(offset).Limit(limit).Find(&groups).Error
	return groups, total, err
}

// 更新主机组
func Update(id uint, updates map[string]interface{}) error {
	return db.Model(&HostGroup{}).Where("id = ?", id).Updates(updates).Error
}

// 删除主机组
func Delete(id uint) error {
	return db.Delete(&HostGroup{}, id).Error
}

// 根据ID查询主机组
func GetByID(id uint) (*HostGroup, error) {
	var group HostGroup
	err := db.First(&group, id).Error
	return &group, err
}
