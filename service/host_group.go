// service/host_group.go
package service

import (
	"cmdb-ops-flow/models"
	"errors"
)

type CreateHostGroupInput struct {
	Name        string `json:"name" binding:"required,min=2,max=50"`
	Description string `json:"description" binding:"max=255"`
}

type UpdateHostGroupInput struct {
	Name        string `json:"name" binding:"required,min=2,max=50"`
	Description string `json:"description" binding:"max=255"`
}

type ListHostGroupsInput struct {
	Name     string `form:"name"`
	Page     int    `form:"page" binding:"required,min=1"`
	PageSize int    `form:"pageSize" binding:"required,min=1,max=100"`
}

// 创建主机组
func Create(input *CreateHostGroupInput) (*models.HostGroup, error) {
	hostGroup := &models.HostGroup{
		Name:        input.Name,
		Description: input.Description,
	}

	err := models.Create(hostGroup)
	if err != nil {
		return nil, err
	}

	return hostGroup, nil
}

// 查询主机组列表
func List(input *ListHostGroupsInput) ([]models.HostGroup, int64, error) {
	offset := (input.Page - 1) * input.PageSize
	return models.List(input.Name, offset, input.PageSize)
}

// 更新主机组
func Update(id uint, input *UpdateHostGroupInput) error {
	updates := map[string]interface{}{
		"name":        input.Name,
		"description": input.Description,
	}
	return models.Update(id, updates)
}

// 删除主机组
func Delete(id uint) error {
	// 检查是否存在关联的主机
	group, err := models.GetByID(id)
	if err != nil {
		return err
	}

	if group.HostCount > 0 {
		return errors.New("该主机组下还有主机，无法删除")
	}

	return models.Delete(id)
}
