# 文件共享管理系统

## 环境要求
- Python 3.10+ 
- Windows操作系统
- 至少2GB可用存储空间

## 依赖安装
```bash
pip install -r requirements.txt
```

## 启动方式
双击运行`StartService.bat`脚本，默认访问地址：http://localhost:8000

## 初始用户
管理员：admin，admin_password；manager,manager_password
普通用户：user,user_password
在app.py中配置  
```python
# 管理员账号密码
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'admin_password'

# 普通用户账号密码
USER_USERNAME = 'user'
USER_PASSWORD = 'user_password'
```
## 功能说明
- 用户权限系统（普通用户/管理员）
- 文件上传下载管理（支持ZIP打包下载）
- 实时磁盘空间监控
- 操作日志审计

## 注意事项
1. 首次使用前必须安装依赖
2. 上传文件默认存储在`downloads`目录
3. 管理员默认凭证：admin/admin（首次登录后请立即修改）
4. 生产环境需修改`app.py`中的secret_key
5. 单文件上传限制为2GB

## 项目结构
关键文件说明：
- `app.py`：主程序入口
- `templates/`：前端页面模板
- `build.py`：打包构建Windows下的exe程序脚本
- `images/`：系统截图文档

## 常见问题
Q：端口冲突如何解决？
A：修改`StartService.bat`中的--port
