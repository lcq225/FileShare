import os
import re
import logging
import shutil
import zipfile
from datetime import datetime
from flask import Flask, render_template, send_file, abort, request, redirect, flash, url_for, session, make_response
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import PasswordField, SubmitField, StringField
from wtforms.validators import DataRequired, Length, EqualTo

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'super_secret_key_123')  # 从环境变量获取密钥

# 配置文件存储目录
DOWNLOAD_FOLDER = 'downloads'
UPLOAD_FOLDER = 'downloads'
app.config['DOWNLOAD_FOLDER'] = DOWNLOAD_FOLDER
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB 文件大小限制

# 配置日志
log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
if os.environ.get('PRODUCTION'):
    # 生产环境：记录到文件
    logging.basicConfig(
        filename='app.log',
        level=logging.INFO,
        format=log_format,
        datefmt='%Y-%m-%d %H:%M:%S',
        encoding='utf-8'
    )
else:
    # 开发环境：输出到控制台
    logging.basicConfig(
        level=logging.INFO,
        format=log_format,
        datefmt='%Y-%m-%d %H:%M:%S'
    )

logger = logging.getLogger('FileShare')

# 用户配置 (从环境变量获取或使用默认值)
USERS = {
    'admin': {
        'password': generate_password_hash(os.environ.get('ADMIN_PASSWORD', 'admin_password')),
        'role': 'admin'
    },
    'manager': {
        'password': generate_password_hash(os.environ.get('MANAGER_PASSWORD', 'manager_password')),
        'role': 'admin'
    },
    'user': {
        'password': generate_password_hash(os.environ.get('USER_PASSWORD', 'user_password')),
        'role': 'user'
    }
}

# 允许上传/下载的文件类型
ALLOWED_EXTENSIONS = {'pdf', 'docx', 'xlsx', 'jpg', 'jpeg', 'png', 'gif', 'zip', 'txt', 'pptx', 'mp4', 'mp3'}

# 密码修改表单
class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('当前密码', validators=[DataRequired()])
    new_password = PasswordField('新密码', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('确认新密码', validators=[DataRequired(), EqualTo('new_password', message='密码必须一致')])
    submit = SubmitField('修改密码')

# 文件重命名表单
class RenameFileForm(FlaskForm):
    new_name = StringField('新文件名', validators=[DataRequired()])
    submit = SubmitField('重命名')

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def secure_filename_zh(filename):
    """安全处理中文文件名"""
    # 保留中文、字母、数字、下划线、点、减号
    filename = re.sub(r'[^a-zA-Z0-9\u4e00-\u9fa5_.-]', '', filename)
    # 移除路径分隔符
    filename = filename.replace('/', '').replace('\\', '')
    # 如果文件名为空，使用时间戳
    if not filename:
        filename = f"file_{datetime.now().strftime('%Y%m%d%H%M%S')}"
    return filename

def get_file_info(filepath):
    """获取文件详细信息"""
    filename = os.path.basename(filepath)
    size_bytes = os.path.getsize(filepath)
    # 智能转换文件大小单位
    if size_bytes < 1024:
        size_str = f"{size_bytes} bytes"
    elif size_bytes < 1024*1024:
        size_str = f"{size_bytes/1024:.1f} KB"
    else:
        size_str = f"{size_bytes/(1024*1024):.1f} MB"
    
    # 获取文件修改时间
    mod_time = os.path.getmtime(filepath)
    mod_date = datetime.fromtimestamp(mod_time).strftime('%Y-%m-%d %H:%M')
    
    # 获取文件类型
    file_ext = filename.split('.')[-1].upper() if '.' in filename else 'UNKNOWN'
    
    # 判断是否可预览
    previewable = file_ext in {'JPG', 'JPEG', 'PNG', 'PDF'}
    
    return {
        'name': filename,
        'size': size_str,
        'type': file_ext,
        'mod_date': mod_date,
        'path': filepath,
        'previewable': previewable
    }

def get_current_user():
    """获取当前用户信息"""
    if 'username' in session:
        return {
            'username': session['username'],
            'role': session.get('role', 'guest'),
            'authenticated': True
        }
    return {
        'username': '匿名用户',
        'role': 'guest',
        'authenticated': False
    }

def check_permission(required_role='user'):
    """检查用户权限"""
    user = get_current_user()
    if required_role == 'admin':
        return user.get('role') == 'admin'
    return user.get('authenticated', False)

@app.route('/')
def index():
    """显示文件下载页面（允许匿名访问）"""
    # 获取当前用户信息
    current_user = get_current_user()
    can_upload = current_user.get('role') == 'admin'
    can_delete = current_user.get('role') == 'admin'
    can_rename = current_user.get('role') == 'admin'
    
    # 获取搜索查询
    search_query = request.args.get('q', '')
    
    files = []
    # 获取下载目录中的文件列表（仅显示允许的文件类型）
    for filename in os.listdir(app.config['DOWNLOAD_FOLDER']):
        path = os.path.join(app.config['DOWNLOAD_FOLDER'], filename)
        if os.path.isfile(path) and allowed_file(filename):
            # 应用搜索过滤
            if search_query.lower() not in filename.lower():
                continue
            files.append(get_file_info(path))
    
    # 按修改时间排序（最新的在最前面）
    files.sort(key=lambda x: os.path.getmtime(x['path']), reverse=True)
    
    # 分页处理
    page = request.args.get('page', 1, type=int)
    per_page = 20
    total_files = len(files)
    total_pages = (total_files + per_page - 1) // per_page
    start_index = (page - 1) * per_page
    end_index = min(start_index + per_page, total_files)
    paginated_files = files[start_index:end_index]
    
    return render_template(
        'index.html', 
        files=paginated_files, 
        user=current_user,
        can_upload=can_upload,
        can_delete=can_delete,
        can_rename=can_rename,
        current_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        search_query=search_query,
        page=page,
        total_pages=total_pages,
        total_files=total_files
    )

@app.route('/download/<filename>')
def download_file(filename):
    """处理文件下载请求（允许匿名访问）"""
    try:
        # 安全处理文件路径
        safe_path = os.path.abspath(app.config['DOWNLOAD_FOLDER'])
        file_path = os.path.join(safe_path, filename)
        
        # 确保文件路径在安全目录内
        if not file_path.startswith(safe_path):
            abort(403, description="禁止访问")
            
        # 检查文件是否存在且是普通文件
        if not os.path.isfile(file_path):
            abort(404)
            
        # 检查文件类型是否允许
        if not allowed_file(filename):
            abort(403, description="此文件类型不允许下载")
        
        # 记录下载日志
        current_user = get_current_user()
        logger.info(f"用户 '{current_user['username']}' 下载了文件: {filename}")
        
        # 发送文件给客户端
        response = make_response(send_file(file_path, as_attachment=True, download_name=filename))
        
        return response
    except Exception as e:
        logger.error(f"下载错误: {str(e)}")
        abort(500)

@app.route('/preview/<filename>')
def preview_file(filename):
    """预览文件（允许匿名访问）"""
    try:
        # 安全处理文件路径
        safe_path = os.path.abspath(app.config['DOWNLOAD_FOLDER'])
        file_path = os.path.join(safe_path, filename)
        
        # 确保文件路径在安全目录内
        if not file_path.startswith(safe_path):
            abort(403, description="禁止访问")
            
        # 检查文件是否存在且是普通文件
        if not os.path.isfile(file_path):
            abort(404)
            
        # 检查文件类型是否允许预览
        file_ext = filename.split('.')[-1].lower() if '.' in filename else ''
        if file_ext not in ['jpg', 'jpeg', 'png', 'pdf']:
            abort(403, description="此文件类型不支持预览")
        
        # 记录预览日志
        current_user = get_current_user()
        logger.info(f"用户 '{current_user['username']}' 预览了文件: {filename}")
        
        # 发送文件给客户端
        if file_ext in ['jpg', 'jpeg', 'png']:
            return send_file(file_path, mimetype=f'image/{file_ext}')
        elif file_ext == 'pdf':
            return send_file(file_path, mimetype='application/pdf')
        
    except Exception as e:
        logger.error(f"预览错误: {str(e)}")
        abort(500)

@app.route('/download-multiple', methods=['POST'])
def download_multiple_files():
    """批量下载文件（打包为ZIP）"""
    try:
        # 获取选择的文件列表
        selected_files = request.form.getlist('selected_files')
        if not selected_files:
            flash('请选择要下载的文件', 'error')
            return redirect(url_for('index'))
        
        # 创建临时ZIP文件
        zip_filename = f"downloads_{datetime.now().strftime('%Y%m%d%H%M%S')}.zip"
        zip_path = os.path.join('temp', zip_filename)
        
        # 确保临时目录存在
        os.makedirs('temp', exist_ok=True)
        
        # 创建ZIP文件
        with zipfile.ZipFile(zip_path, 'w') as zipf:
            for filename in selected_files:
                safe_path = os.path.abspath(app.config['DOWNLOAD_FOLDER'])
                file_path = os.path.join(safe_path, filename)
                
                # 安全检查
                if not file_path.startswith(safe_path) or not os.path.isfile(file_path):
                    continue
                
                # 添加文件到ZIP
                zipf.write(file_path, arcname=filename)
        
        # 记录下载日志
        current_user = get_current_user()
        logger.info(f"用户 '{current_user['username']}' 批量下载了 {len(selected_files)} 个文件")
        
        # 发送ZIP文件
        return send_file(
            zip_path,
            as_attachment=True,
            download_name=zip_filename,
            mimetype='application/zip'
        )
    except Exception as e:
        logger.error(f"批量下载错误: {str(e)}")
        flash('批量下载文件时出错', 'error')
        return redirect(url_for('index'))

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    """处理文件上传（需要管理员权限）"""
    # 检查用户权限
    if not check_permission('admin'):
        flash('您没有上传文件的权限', 'error')
        return redirect(url_for('index'))
    
    current_user = get_current_user()
    
    if request.method == 'POST':
        # 检查是否有文件被上传
        if 'files' not in request.files:
            flash('没有选择文件', 'error')
            return redirect(request.url)
        
        files = request.files.getlist('files')
        uploaded_files = []
        
        for file in files:
            # 检查是否选择了文件
            if file.filename == '':
                continue
            
            # 检查文件类型和文件名
            if file and allowed_file(file.filename):
                # 安全处理中文文件名
                original_filename = file.filename
                filename = secure_filename_zh(original_filename)
                
                # 检查文件是否已存在
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                if os.path.exists(file_path):
                    # 生成唯一文件名（添加时间戳）
                    base, ext = os.path.splitext(filename)
                    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                    filename = f"{base}_{timestamp}{ext}"
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                
                # 保存文件
                file.save(file_path)
                uploaded_files.append(filename)
                
                # 记录上传日志
                logger.info(f"用户 '{current_user['username']}' 上传了文件: {original_filename} -> {filename}")
        
        if uploaded_files:
            flash(f'成功上传 {len(uploaded_files)} 个文件', 'success')
        else:
            flash('没有文件被上传', 'error')
        
        return redirect(url_for('index'))
    
    # GET请求显示上传表单
    return render_template('upload.html', user=current_user)

@app.route('/delete-multiple', methods=['POST'])
def delete_multiple_files():
    """批量删除文件（需要管理员权限）"""
    # 检查用户权限
    if not check_permission('admin'):
        flash('您没有删除文件的权限', 'error')
        return redirect(url_for('index'))
    
    current_user = get_current_user()
    
    try:
        # 获取选择的文件列表
        selected_files = request.form.getlist('selected_files')
        if not selected_files:
            flash('请选择要删除的文件', 'error')
            return redirect(url_for('index'))
        
        deleted_count = 0
        # 安全处理文件路径
        safe_path = os.path.abspath(app.config['DOWNLOAD_FOLDER'])
        
        for filename in selected_files:
            file_path = os.path.join(safe_path, filename)
            
            # 确保文件路径在安全目录内
            if not file_path.startswith(safe_path):
                continue
            
            # 检查文件是否存在
            if os.path.isfile(file_path):
                # 删除文件
                os.remove(file_path)
                deleted_count += 1
                
                # 记录删除日志
                logger.info(f"用户 '{current_user['username']}' 删除了文件: {filename}")
        
        if deleted_count > 0:
            flash(f'成功删除 {deleted_count} 个文件', 'success')
        else:
            flash('没有文件被删除', 'error')
            
    except Exception as e:
        logger.error(f"批量删除错误: {str(e)}")
        flash('批量删除文件时出错', 'error')
    
    return redirect(url_for('index'))

@app.route('/rename/<filename>', methods=['GET', 'POST'])
def rename_file(filename):
    """重命名文件（需要管理员权限）"""
    # 检查用户权限
    if not check_permission('admin'):
        flash('您没有重命名文件的权限', 'error')
        return redirect(url_for('index'))
    
    current_user = get_current_user()
    
    # 安全处理文件路径
    safe_path = os.path.abspath(app.config['DOWNLOAD_FOLDER'])
    old_path = os.path.join(safe_path, filename)
    
    # 确保文件路径在安全目录内
    if not old_path.startswith(safe_path):
        abort(403, description="禁止访问")
    
    # 检查文件是否存在
    if not os.path.isfile(old_path):
        flash(f'文件 "{filename}" 不存在', 'error')
        return redirect(url_for('index'))
    
    form = RenameFileForm()
    
    if form.validate_on_submit():
        new_name = secure_filename_zh(form.new_name.data)
        
        # 检查新文件名是否包含扩展名
        if '.' not in new_name:
            flash('文件名必须包含扩展名（如：.pdf, .docx）', 'error')
            return render_template('rename.html', form=form, filename=filename, user=current_user)
        
        # 检查文件扩展名是否允许
        if not allowed_file(new_name):
            flash('不允许的文件类型', 'error')
            return render_template('rename.html', form=form, filename=filename, user=current_user)
        
        new_path = os.path.join(safe_path, new_name)
        
        # 检查新文件是否已存在
        if os.path.exists(new_path):
            flash('该文件名已存在', 'error')
            return render_template('rename.html', form=form, filename=filename, user=current_user)
        
        try:
            # 重命名文件
            os.rename(old_path, new_path)
            
            # 记录重命名日志
            logger.info(f"用户 '{current_user['username']}' 将文件 '{filename}' 重命名为 '{new_name}'")
            
            flash(f'文件已成功重命名为 "{new_name}"', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            logger.error(f"重命名错误: {str(e)}")
            flash(f'重命名文件时出错: {str(e)}', 'error')
    
    # 预填充当前文件名（包含扩展名）
    form.new_name.data = filename
    
    return render_template('rename.html', form=form, filename=filename, user=current_user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """用户登录"""
    # 如果用户已登录，重定向到首页
    if get_current_user()['authenticated']:
        return redirect(url_for('index'))
    
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # 验证用户凭证
        if username in USERS and check_password_hash(USERS[username]['password'], password):
            # 设置会话
            session['username'] = username
            session['role'] = USERS[username]['role']
            session.permanent = True  # 持久会话
            
            # 记录登录日志
            logger.info(f"用户 '{username}' 登录成功")
            
            flash('登录成功！', 'success')
            return redirect(url_for('index'))
        else:
            error = '用户名或密码错误'
            # 记录登录失败日志
            logger.warning(f"登录失败: 用户名 '{username}'")
    
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    """用户退出"""
    username = session.get('username', '未知用户')
    
    # 清除会话
    session.pop('username', None)
    session.pop('role', None)
    
    # 记录退出日志
    logger.info(f"用户 '{username}' 已退出")
    
    flash('您已成功退出', 'success')
    return redirect(url_for('index'))

@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    """修改密码（需要登录）"""
    # 检查用户是否登录
    if not get_current_user()['authenticated']:
        flash('请先登录', 'error')
        return redirect(url_for('login'))
    
    current_user = get_current_user()
    form = ChangePasswordForm()
    
    if form.validate_on_submit():
        # 验证当前密码
        if not check_password_hash(USERS[current_user['username']]['password'], form.current_password.data):
            flash('当前密码错误', 'error')
            return render_template('change_password.html', form=form, user=current_user)
        
        # 更新密码
        USERS[current_user['username']]['password'] = generate_password_hash(form.new_password.data)
        
        # 记录密码修改日志
        logger.info(f"用户 '{current_user['username']}' 修改了密码")
        
        flash('密码修改成功！', 'success')
        return redirect(url_for('index'))
    
    return render_template('change_password.html', form=form, user=current_user)

@app.route('/logs')
def view_logs():
    """查看日志（需要管理员权限）"""
    # 检查用户权限
    if not check_permission('admin'):
        flash('您没有查看日志的权限', 'error')
        return redirect(url_for('index'))
    
    try:
        # 读取日志文件内容（使用错误忽略策略）
        with open('app.log', 'r', encoding='utf-8', errors='ignore') as log_file:
            log_content = log_file.readlines()
    except Exception as e:
        log_content = [f'无法读取日志文件: {str(e)}']
    
    # 反转日志，最新的在最上面
    log_content.reverse()
    
    return render_template('logs.html', logs=log_content, user=get_current_user())

@app.route('/clear-temp')
def clear_temp():
    """清除临时文件（需要管理员权限）"""
    # 检查用户权限
    if not check_permission('admin'):
        return '', 403
    
    try:
        # 删除临时目录中的所有文件
        temp_dir = 'temp'
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
            os.makedirs(temp_dir)
            logger.info(f"临时目录已清空")
            return '临时文件已清除', 200
        return '临时目录不存在', 404
    except Exception as e:
        logger.error(f"清除临时文件错误: {str(e)}")
        return f'错误: {str(e)}', 500

@app.route('/disk-usage')
def disk_usage():
    """查看磁盘使用情况（需要管理员权限）"""
    # 检查用户权限
    if not check_permission('admin'):
        flash('您没有查看磁盘使用情况的权限', 'error')
        return redirect(url_for('index'))
    
    try:
        # 获取磁盘使用情况
        total, used, free = shutil.disk_usage(app.config['DOWNLOAD_FOLDER'])
        
        # 转换为GB
        total_gb = total / (2**30)
        used_gb = used / (2**30)
        free_gb = free / (2**30)
        usage_percent = (used / total) * 100
        
        return render_template('disk_usage.html', 
                              total=total_gb, 
                              used=used_gb, 
                              free=free_gb,
                              percent=usage_percent,
                              user=get_current_user())
    except Exception as e:
        logger.error(f"获取磁盘使用情况错误: {str(e)}")
        flash('获取磁盘使用情况时出错', 'error')
        return redirect(url_for('index'))

if __name__ == '__main__':
    # 确保下载目录存在
    os.makedirs(DOWNLOAD_FOLDER, exist_ok=True)
    os.makedirs('temp', exist_ok=True)  # 临时目录
    
    # 创建示例文件（实际使用时可以删除）
    sample_files = [
        "示例文档.pdf",
        "数据报告.xlsx",
        "项目笔记.txt",
        "截图.png"
    ]
    for file in sample_files:
        file_path = os.path.join(DOWNLOAD_FOLDER, file)
        if not os.path.exists(file_path):
            open(file_path, 'a').close()
    
    # 启动开发服务器
    app.run(host='0.0.0.0', port=5000, debug=True)