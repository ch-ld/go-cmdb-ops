

  <h1 align="center">go-cmdb-ops</h1>
  <p align="center">
 此项目架构完全参考cmdb-ops-flow，是cmdb-ops-flow的优化版本，完成了此版本的一些功能新增和优化。
    <br />
     <br />
    本项目后端参考： https://github.com/qishu321/cmdb-ops-flow
	<br />
	此项目前端地址： https://github.com/ch-ld/go-cmdb-ops-web

  </p>
    <br />

## 技术栈 

#### 后端 Golang 1.19

- Gin 1.9.1             [(Web框架)](https://gin-gonic.com/zh-cn/)
- GORM v1.9.16     [(ORM)](https://gorm.io/zh_CN/)
- MySQL 8.0             [(数据库)](https://www.mysql.com/)

#### 前端 Vue.js 3

- vue-admin-template                     [(后台前端)](http://panjiachen.github.io/vue-admin-template)

#### 已实现的功能
- [x] 内部导航栏
- [x] 用户中心
  - [x] 用户管理
  - [x] 角色管理
- [x] CMDB
  - [x] 主机管理
    - [x] 新增主机
    - [x] 导入主机
    - [x] 同步云主机
      - [ ] 阿里云
      - [ ] AWS
  - [x] 主机组管理
  - [x] 远程操作
    - [x] wehssh
    - [x] 批量执行命令
    - [x] SFTP
      - [x] 文件上传
      - [x] 创建文件
      - [x] 文件下载
      - [x] 文件批量删除
- [ ] k8s的多集群管理

## 部署方法

###安装编译

```go
# clone
git clone https://github.com/ch-ld/go-cmdb-ops
##整体目录结构
├─api               api
├─conf              配置文件
├─middleware        中间件
├─models            数据库
├─router            路径
├─service           业务逻辑
├─test
└─utils             通用工具
    ├─common        加密解密
    ├─msg           状态码
    ├─result        状态码封装
    └─ssh           ssh
```


#### 如何参与开源项目

贡献使开源社区成为一个学习、激励和创造的绝佳场所。你所作的任何贡献都是**非常感谢**的。


1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### 版本控制

该项目使用Git进行版本管理。您可以在repository参看当前可用版本。

### 作者

暂无


### 版权说明

该项目签署了MIT 授权许可

### 鸣谢

[cmdb-ops-flow](https://github.com/qishu321/cmdb-ops-flow) 强烈感谢cmdb-ops-flow提供的基本框架，开始所有的流程和思路都是基于这个基础之上来配置的

[vue-admin-template](http://panjiachen.github.io/vue-admin-template) 非常感谢vue-admin-template的开源项目

[webssh](https://github.com/widaT/webssh)               非常感谢widaT的webssh开源项目

[shaojintian README模板](https://github.com/shaojintian/Best_README_template)  非常感谢 shaojintian README模板

