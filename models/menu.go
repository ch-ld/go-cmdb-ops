package models

import (
	"fmt"
	"gorm.io/datatypes"
)

// 用于vue-admin 动态路由展示的
// Menu 菜单表
type Menu struct {
	MenuId    uint           `gorm:"primaryKey"`
	Path      string         `json:"path"`                                // 菜单路径
	Component string         `json:"component"`                           // 组件
	Redirect  string         `json:"redirect"`                            // 重定向路径
	Name      string         `json:"name"`                                // 菜单名称
	Meta      datatypes.JSON `json:"meta" gorm:"size:1024"`               // 元数据
	Children  []Menu         `json:"children" gorm:"foreignKey:ParentID"` //  子菜单 `gorm:"children"`
	ParentID  uint           `json:"parent_id" gorm:"index"`              // 父菜单ID
}

//// Meta 元数据
//type Meta struct {
//	Title string `json:"title"` // 标题
//	Icon  string `json:"icon"`  // 图标
//}
//
//// Child 子菜单
//type Child struct {
//	Path      string `json:"path"`      // 菜单路径
//	Component string `json:"component"` // 组件
//	Name      string `json:"name"`      // 菜单名称
//}

func InitMenuData() {
	var count int64
	db.Model(&Menu{}).Count(&count)
	if count > 0 {
		fmt.Println("Menu表中已有初始数据，跳过")
	} else {
		// 父级菜单
		exampleMenuParent := Menu{
			MenuId:    1,
			Path:      "/example",
			Component: "Layout",
			Redirect:  "/example/table",
			Name:      "Example",
			Meta:      datatypes.JSON(`{ "title": "案例", "icon": "el-icon-s-help", "roles": "admin" }`),
		}

		// 子级菜单1
		exampleMenuChild1 := Menu{
			MenuId:    2,
			Path:      "table",
			Component: "/table/index",
			Name:      "Table",
			Meta:      datatypes.JSON(`{ "title": "表格", "icon": "table", "roles": "admin" }`),
			ParentID:  1,
		}

		// 子级菜单2
		exampleMenuChild2 := Menu{
			MenuId:    3,
			Path:      "tree",
			Component: "/tree/index",
			Name:      "Tree",
			Meta:      datatypes.JSON(`{ "title": "树状表格", "icon": "tree", "roles": "admin" }`),
			ParentID:  1,
		}

		//form子菜单
		formMenu := Menu{
			MenuId:    4,
			Path:      "/form",
			Name:      "Form",
			Component: "Layout",
		}

		formMenuChildren1 := Menu{
			MenuId:    5,
			Path:      "index",
			Name:      "Form",
			Component: "/form/index",
			Meta:      datatypes.JSON(`{ "title": "表单", "icon": "form", "roles": "admin"}`),
			ParentID:  4,
		}

		//nestedMenu := Menu{
		//	Path:      "/nested",
		//	Component: "Layout",
		//	Redirect:  "/nested/menu1",
		//	Name:      "Nested",
		//	Meta:      datatypes.JSON(`{ "title": "Nested", "icon": "nested" }`),
		//	Children: datatypes.JSON(`[
		//				{
		//					"path": "menu1",
		//					"component": "() => import('@/views/nested/menu1/index')",
		//					"name": "Menu1",
		//					"meta": { "title": "Menu1" },
		//					"children": [
		//						{
		//							"path": "menu1-1",
		//							"component": "() => import('@/views/nested/menu1/menu1-1')",
		//							"name": "Menu1-1",
		//							"meta": { "title": "Menu1-1" }
		//						},
		//						{
		//							"path": "menu1-2",
		//							"component": "() => import('@/views/nested/menu1/menu1-2')",
		//							"name": "Menu1-2",
		//							"meta": { "title": "Menu1-2" },
		//							"children": [
		//								{
		//									"path": "menu1-2-1",
		//									"component": "() => import('@/views/nested/menu1/menu1-2/menu1-2-1')",
		//									"name": "Menu1-2-1",
		//									"meta": { "title": "Menu1-2-1" }
		//								},
		//								{
		//									"path": "menu1-2-2",
		//									"component": "() => import('@/views/nested/menu1/menu1-2/menu1-2-2')",
		//									"name": "Menu1-2-2",
		//									"meta": { "title": "Menu1-2-2" }
		//								}
		//							]
		//						},
		//						{
		//							"path": "menu1-3",
		//							"component": "() => import('@/views/nested/menu1/menu1-3')",
		//							"name": "Menu1-3",
		//							"meta": { "title": "Menu1-3" }
		//						}
		//					]
		//				},
		//				{
		//					"path": "menu2",
		//					"component": "() => import('@/views/nested/menu2/index')",
		//					"name": "Menu2",
		//					"meta": { "title": "menu2" }
		//				}
		//			]`),
		//}
		//
		//externalLinkMenu := Menu{
		//	Path:      "external-link",
		//	Component: "Layout",
		//	Children: datatypes.JSON(`[
		//				{
		//					"path": "https://panjiachen.github.io/vue-element-admin-site/#/",
		//					"meta": { "title": "External Link", "icon": "link" }
		//				}
		//			]`),
		//}
		db.Create(&exampleMenuParent)
		db.Create(&exampleMenuChild1)
		db.Create(&exampleMenuChild2)
		db.Create(&formMenu)
		db.Create(&formMenuChildren1)
		fmt.Println("数据插入成功！")
	}
}
