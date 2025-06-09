# EasyTier

为 Hyacinth 项目提供的修改版本 EasyTier 核心，加入了用户权限管理功能，通过连接 MySQL 数据库来决定用户是否有权限访问特定的虚拟网络。

构建、部署方法见原版 EasyTier 项目，要连接 MySQL 数据库，请在启动参数中加入`db_url`字段。数据库格式详见 hyacinth-backend 项目。

项目基于 EasyTier 2.2.4 版本，EasyTier 近段时间推出了 2.3.0 Release，可能会有一些不兼容的改动，尚未进行测试，请尽量使用 2.2.4 版本客户端进行测试。