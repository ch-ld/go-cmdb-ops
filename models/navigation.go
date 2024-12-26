package models

import (
	"errors"
	"fmt"
	"log"
)

type Navigation struct {
	ID        uint   `gorm:"primaryKey" json:"id"`
	Title     string `json:"title"`
	Desc      string `json:"desc"`
	Logo      string `json:"logo"`
	Links     []Link `gorm:"foreignKey:NavigationID" json:"links"`
	SortOrder int    `json:"sort_order"` // 新增的排序字段
}

type Link struct {
	ID           uint   `gorm:"primaryKey" json:"-"`
	NavigationID uint   `json:"-"`
	Name         string `json:"name"`
	URL          string `json:"url"`
}

var navigationRecords = []Navigation{
	{
		ID:    1,
		Title: "导航 1",
		Desc:  "描述 1",
		Logo:  "",
		Links: []Link{
			{Name: "百度", URL: "https://www.baidu.com"},
		},
		SortOrder: 0,
	},
	{
		ID:    2,
		Title: "导航 2",
		Desc:  "描述 2",
		Logo:  "",
		Links: []Link{
			{Name: "谷歌", URL: "https://www.google.com"},
		},
		SortOrder: 1,
	},
}

func InitNavigationData() {
	var navigationRecords = []Navigation{
		{
			ID:    1,
			Title: "导航 1",
			Desc:  "描述 1",
			Logo:  "",
			Links: []Link{
				{Name: "百度", URL: "https://www.baidu.com"},
			},
		},
		{
			ID:    2,
			Title: "导航 2",
			Desc:  "描述 2",
			Logo:  "",
			Links: []Link{
				{Name: "谷歌", URL: "https://www.google.com"},
			},
		},
	}
	for _, navigationRecord := range navigationRecords {
		db.Create(&navigationRecord)
	}
}

func GetNavigationRecords() ([]Navigation, error) {
	var records []Navigation
	err := db.Preload("Links").Order("sort_order asc").Find(&records).Error
	return records, err
}

func CreateNavigationRecord(newRecord Navigation) (interface{}, error) {
	var maxSortOrder int
	_ = db.Table("navigation").Select("max(sort_order)").Row().Scan(&maxSortOrder)
	newRecord.SortOrder = maxSortOrder + 1 // 按排序顺序添加

	err := db.Create(&newRecord).Error
	return newRecord, err
}

func UpdateNavigationRecord(updatedRecord Navigation) (interface{}, error) {
	// 确保更新主记录
	if err := db.Model(&Navigation{}).Where("id = ?", updatedRecord.ID).Updates(updatedRecord).Error; err != nil {
		log.Fatal("Error updating navigation record:", err)
		return nil, err
	}

	// 删除旧的 Links 数据
	if err := db.Model(&Link{}).Where("navigation_id = ?", updatedRecord.ID).Delete(&Link{}).Error; err != nil {
		log.Fatal("Error deleting old links:", err)
		return nil, err
	}

	// 为当前记录添加新的 Links 数据
	for _, link := range updatedRecord.Links {
		link.NavigationID = updatedRecord.ID // 关联到更新的 Navigation
		if err := db.Create(&link).Error; err != nil {
			log.Fatal("Error adding link:", err)
			return nil, err
		}
	}

	// 重新预加载 Links 数据
	var updatedNav Navigation
	if err := db.Preload("Links").First(&updatedNav, updatedRecord.ID).Error; err != nil {
		log.Fatal("Error reloading updated navigation:", err)
		return nil, err
	}

	return updatedNav, nil
}

func SaveNavigations(records []Navigation) error {
	return db.Save(&records).Error
}

func DeleteNavigationRecord(id uint) error {
	if err := db.Delete(&Navigation{}, id).Error; err != nil {
		log.Fatal("Error deleting navigation record")
		return err
	}
	return nil
}

// SortNavigationRecord 处理排序逻辑
func SortNavigationRecord(id uint, direction string) error {
	// 获取当前记录
	var currentRecord Navigation
	if err := db.First(&currentRecord, id).Error; err != nil {
		return errors.New("record not found")
	}
	fmt.Println("current_record:", currentRecord)

	// 获取相邻的记录
	var neighbor Navigation
	var err error
	if direction == "left" {
		// 获取当前记录之前的记录
		err = db.Where("id < ?", currentRecord.ID).Order("id desc").First(&neighbor).Error
		fmt.Println("neighbor_right:", neighbor)
	} else if direction == "right" {
		// 获取当前记录之后的记录
		err = db.Where("id > ?", currentRecord.ID).Order("id asc").First(&neighbor).Error
		fmt.Println("neighbor_left:", neighbor)
	} else {
		return errors.New("invalid direction")
	}

	if err != nil {
		return errors.New("no neighbor found")
	}

	// 交换排序位置
	if direction == "right" || direction == "left" {
		// 向上或向下排序：交换 currentRecord 和 neighbor 的排序字段
		swapSortOrder(&currentRecord, &neighbor)
		// 保存更新后的记录
		if err := db.Save(&currentRecord).Error; err != nil {
			return err
		}
		if err := db.Save(&neighbor).Error; err != nil {
			return err
		}
	}

	return nil
}

// swapSortOrder 交换两个记录的排序字段
func swapSortOrder(currentRecord, neighbor *Navigation) {
	// 假设 Navigation 结构中有一个 SortOrder 字段，用于控制排序
	currentSortOrder := currentRecord.SortOrder
	currentRecord.SortOrder = neighbor.SortOrder
	neighbor.SortOrder = currentSortOrder
}
