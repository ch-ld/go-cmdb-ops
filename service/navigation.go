package service

import (
	"cmdb-ops-flow/models"
)

func GetNavigationRecords() (data interface{}, err error) {
	return models.GetNavigationRecords()
}

func CreateNavigationRecord(newRecord models.Navigation) (data interface{}, err error) {
	data, err = models.CreateNavigationRecord(newRecord)
	return data, err
}

func UpdateNavigationRecord(updatedRecord models.Navigation) (data interface{}, err error) {
	data, err = models.UpdateNavigationRecord(updatedRecord)
	return data, err
}

func DeleteNavigationRecord(id uint) (err error) {
	err = models.DeleteNavigationRecord(id)
	return err
}

//func SortNavigation(ID uint, sortDirection string) ([]models.Navigation, error) {
//	// 获取所有导航记录
//	records, err := models.GetNavigationRecords()
//	if err != nil {
//		return nil, err
//	}
//
//	// 根据ID查找记录并进行排序
//	for i := range records {
//		if records[i].ID == ID {
//			if sortDirection == "up" && i > 0 {
//				// 与上一个记录交换
//				records[i], records[i-1] = records[i-1], records[i]
//			} else if sortDirection == "down" && i < len(records)-1 {
//				// 与下一个记录交换
//				records[i], records[i+1] = records[i+1], records[i]
//			} else {
//				return nil, errors.New("无效的排序方向或位置")
//			}
//
//			// 保存更新后的记录
//			err := models.SaveNavigations(records)
//			if err != nil {
//				return nil, err
//			}
//
//			return records, nil
//		}
//	}
//	return nil, errors.New("未找到该记录")
//}
