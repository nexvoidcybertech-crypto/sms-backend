import os
from datetime import datetime, timedelta
from functools import wraps
from bson import ObjectId
import uuid
from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient, ASCENDING, DESCENDING
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from dotenv import load_dotenv
import logging
import json
from bson import json_util
import traceback

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Enhanced CORS configuration
CORS(app, 
     resources={
         r"/api/*": {
             "origins": ["http://localhost:3000", "http://localhost:5000", "http://127.0.0.1:5500"],
             "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
             "allow_headers": ["Authorization", "Content-Type", "X-Requested-With"],
             "expose_headers": ["Authorization"],
             "supports_credentials": True,
             "max_age": 600
         }
     })

# ------------------------
# Configuration
# ------------------------
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'uganda-school-system-secret-key-2024')
app.config['MONGO_URI'] = os.getenv('MONGO_URI', 'mongodb+srv://nexvoidcybertech_db_user:HMONzfxWsd4WMEW1@nexvoid.te09d8a.mongodb.net/nexvoid?retryWrites=true&w=majority')
app.config['TOKEN_EXPIRY_HOURS'] = 24
app.config['DEBUG'] = os.getenv('DEBUG', 'False').lower() == 'true'

# ------------------------
# Custom JSON Encoder for ObjectId and datetime
# ------------------------
class MongoJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, ObjectId):
            return str(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, bytes):
            return obj.decode('utf-8')
        if isinstance(obj, uuid.UUID):
            return str(obj)
        return super().default(obj)

app.json_encoder = MongoJSONEncoder

# ------------------------
# MongoDB connection with error handling
# ------------------------
try:
    client = MongoClient(
        app.config['MONGO_URI'], 
        serverSelectionTimeoutMS=10000,
        connectTimeoutMS=10000,
        socketTimeoutMS=10000,
        maxPoolSize=50,
        retryWrites=True,
        w='majority'
    )
    
    # Test connection
    client.server_info()
    db = client["uganda_school_management"]
    
    # Collections with validation
    students = db.students
    staff = db.staff
    classes = db.classes
    grades = db.grades
    users = db.users
    attendance = db.attendance
    audit_logs = db.audit_logs
    
    # Create indexes for better performance
    students.create_index([("name", ASCENDING)])
    students.create_index([("class_id", ASCENDING)])
    students.create_index([("admission_year", DESCENDING)])
    students.create_index([("status", ASCENDING)])
    students.create_index([("name", "text"), ("_id", "text")])
    
    staff.create_index([("name", ASCENDING)])
    staff.create_index([("department", ASCENDING)])
    staff.create_index([("role", ASCENDING)])
    
    grades.create_index([("student_id", ASCENDING), ("subject", ASCENDING)])
    grades.create_index([("class_id", ASCENDING)])
    grades.create_index([("academic_year", DESCENDING)])
    grades.create_index([("term", ASCENDING)])
    
    classes.create_index([("name", ASCENDING)])
    classes.create_index([("level", ASCENDING)])
    classes.create_index([("academic_year", DESCENDING)])
    
    attendance.create_index([("student_id", ASCENDING), ("date", DESCENDING)])
    attendance.create_index([("class_id", ASCENDING), ("date", DESCENDING)])
    
    users.create_index([("role", ASCENDING)])
    
    audit_logs.create_index([("timestamp", DESCENDING)])
    audit_logs.create_index([("entity_type", ASCENDING), ("entity_id", ASCENDING)])
    audit_logs.create_index([("user_id", ASCENDING)])
    
    logger.info("✅ Successfully connected to MongoDB Atlas")
    logger.info(f"Database: {db.name}")
    logger.info(f"Collections: {db.list_collection_names()}")
    
except Exception as e:
    logger.error(f"❌ Failed to connect to MongoDB: {e}")
    logger.error(traceback.format_exc())
    raise

# ------------------------
# Helper Functions
# ------------------------
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        
        if not token:
            return jsonify({'error': 'Authentication token is missing'}), 401
        
        try:
            # Decode token
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            
            # Get user from database
            current_user = users.find_one({'_id': data['user_id']})
            if not current_user:
                return jsonify({'error': 'User not found'}), 401
            
            if not current_user.get('is_active', True):
                return jsonify({'error': 'Account is deactivated'}), 403
            
            # Attach user to request context
            request.current_user = current_user
            
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired. Please login again.'}), 401
        except jwt.InvalidTokenError as e:
            logger.error(f"Invalid token: {e}")
            return jsonify({'error': 'Invalid authentication token'}), 401
        except Exception as e:
            logger.error(f"Token validation error: {e}")
            return jsonify({'error': 'Token validation failed'}), 401
        
        return f(*args, **kwargs)
    return decorated

def role_required(*required_roles):
    def decorator(f):
        @wraps(f)
        @token_required
        def decorated(*args, **kwargs):
            user_role = request.current_user.get('role')
            
            if user_role not in required_roles:
                logger.warning(f"Unauthorized access attempt by {request.current_user['email']} (role: {user_role})")
                return jsonify({'error': 'Insufficient permissions'}), 403
            
            return f(*args, **kwargs)
        return decorated
    return decorator

def log_audit(action, entity_type, entity_id, changes=None):
    """Log changes for audit trail"""
    try:
        user_id = request.current_user.get('_id') if hasattr(request, 'current_user') else 'system'
        
        audit_record = {
            '_id': str(uuid.uuid4()),
            'user_id': user_id,
            'user_email': request.current_user.get('email', 'system') if hasattr(request, 'current_user') else 'system',
            'action': action,
            'entity_type': entity_type,
            'entity_id': entity_id,
            'changes': changes or {},
            'timestamp': datetime.utcnow(),
            'ip_address': request.remote_addr,
            'user_agent': request.user_agent.string if request.user_agent else 'unknown'
        }
        
        audit_logs.insert_one(audit_record)
        logger.info(f"Audit log: {action} {entity_type} {entity_id} by {user_id}")
        
    except Exception as e:
        logger.error(f"Failed to write audit log: {e}")

def require_json():
    if not request.is_json:
        return jsonify({'error': 'Content-Type must be application/json'}), 415
    return None

def serialize_document(doc):
    """Convert MongoDB document to JSON serializable format"""
    if not doc:
        return None
    
    # Use json_util for better serialization
    return json.loads(json_util.dumps(doc))

def get_current_user():
    """Get current user from request context"""
    return getattr(request, 'current_user', None)

def validate_email(email):
    """Simple email validation"""
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_phone(phone):
    """Simple phone validation for Uganda"""
    import re
    pattern = r'^\+256[0-9]{9}$|^0[0-9]{9}$'
    return re.match(pattern, phone) is not None

def hash_password(password):
    """Hash a password for storing."""
    return generate_password_hash(password)

# ------------------------
# Middleware
# ------------------------
@app.before_request
def before_request():
    """Log request details"""
    if request.endpoint and 'static' not in request.endpoint:
        logger.debug(f"Request: {request.method} {request.path} - {request.remote_addr}")

@app.after_request
def after_request(response):
    """Add security headers"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # CORS headers
    if request.method == 'OPTIONS':
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Authorization, Content-Type'
    
    return response

# ------------------------
# Auth Endpoints
# ------------------------
@app.route('/api/auth/register', methods=['POST'])
def register():
    try:
        require_json()
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['email', 'password', 'name', 'role']
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            return jsonify({'error': f'Missing required fields: {", ".join(missing_fields)}'}), 400
        
        # Validate email
        if not validate_email(data['email']):
            return jsonify({'error': 'Invalid email format'}), 400
        
        # Validate role
        if data['role'] not in ['admin', 'teacher', 'staff']:
            return jsonify({'error': 'Invalid role. Must be one of: admin, teacher, staff'}), 400
        
        # Check if user exists
        if users.find_one({'email': data['email']}):
            return jsonify({'error': 'User with this email already exists'}), 409
        
        # Validate password strength
        password = data['password']
        if len(password) < 8:
            return jsonify({'error': 'Password must be at least 8 characters long'}), 400
        
        # Create user
        user_id = str(uuid.uuid4())
        user = {
            '_id': user_id,
            'email': data['email'].lower().strip(),
            'password': hash_password(password),
            'name': data['name'].strip(),
            'role': data['role'],
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow(),
            'is_active': True,
            'last_login': None,
            'profile_picture': data.get('profile_picture'),
            'phone': data.get('phone'),
            'department': data.get('department'),
            'bio': data.get('bio', '')
        }
        
        users.insert_one(user)
        
        # Remove password from response
        user.pop('password', None)
        
        logger.info(f"✅ New user registered: {user['email']} ({user['role']})")
        
        return jsonify({
            'message': 'User registered successfully',
            'user': serialize_document(user)
        }), 201
        
    except Exception as e:
        logger.error(f"Registration error: {e}")
        logger.error(traceback.format_exc())
        return jsonify({'error': 'Internal server error during registration'}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        require_json()
        data = request.get_json()
        
        # Validate required fields
        if not data or 'email' not in data or 'password' not in data:
            return jsonify({'error': 'Email and password are required'}), 400
        
        email = data['email'].lower().strip()
        password = data['password']
        
        # Find user
        user = users.find_one({'email': email})
        if not user:
            logger.warning(f"Login attempt with non-existent email: {email}")
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Check password
        if not check_password_hash(user['password'], password):
            logger.warning(f"Invalid password attempt for: {email}")
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Check if user is active
        if not user.get('is_active', True):
            return jsonify({'error': 'Account is deactivated. Contact administrator.'}), 403
        
        # Update last login
        users.update_one(
            {'_id': user['_id']},
            {'$set': {'last_login': datetime.utcnow()}}
        )
        
        # Generate token
        token_payload = {
            'user_id': str(user['_id']),
            'email': user['email'],
            'role': user['role'],
            'name': user.get('name', ''),
            'exp': datetime.utcnow() + timedelta(hours=app.config['TOKEN_EXPIRY_HOURS'])
        }
        
        token = jwt.encode(token_payload, app.config['SECRET_KEY'])
        
        # Prepare user data for response
        user_data = serialize_document(user)
        user_data.pop('password', None)
        
        logger.info(f"✅ User logged in: {email} ({user['role']})")
        
        return jsonify({
            'token': token,
            'user': user_data,
            'expires_in': app.config['TOKEN_EXPIRY_HOURS'] * 3600,
            'token_type': 'Bearer'
        })
        
    except Exception as e:
        logger.error(f"Login error: {e}")
        logger.error(traceback.format_exc())
        return jsonify({'error': 'Internal server error during login'}), 500

@app.route('/api/auth/change-password', methods=['POST'])
@token_required
def change_password():
    try:
        require_json()
        data = request.get_json()
        
        current_user = get_current_user()
        
        # Validate required fields
        required_fields = ['current_password', 'new_password']
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            return jsonify({'error': f'Missing required fields: {", ".join(missing_fields)}'}), 400
        
        # Verify current password
        user = users.find_one({'_id': current_user['_id']})
        if not check_password_hash(user['password'], data['current_password']):
            return jsonify({'error': 'Current password is incorrect'}), 400
        
        # Validate new password
        new_password = data['new_password']
        if len(new_password) < 8:
            return jsonify({'error': 'New password must be at least 8 characters long'}), 400
        
        # Update password
        hashed_password = hash_password(new_password)
        users.update_one(
            {'_id': current_user['_id']},
            {'$set': {
                'password': hashed_password,
                'updated_at': datetime.utcnow()
            }}
        )
        
        logger.info(f"✅ Password changed for user: {current_user['email']}")
        
        return jsonify({'message': 'Password changed successfully'})
        
    except Exception as e:
        logger.error(f"Password change error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/auth/me', methods=['GET'])
@token_required
def get_current_user_profile():
    """Get current user profile"""
    try:
        current_user = get_current_user()
        user_data = serialize_document(current_user)
        user_data.pop('password', None)
        
        return jsonify({'user': user_data})
        
    except Exception as e:
        logger.error(f"Get profile error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/auth/logout', methods=['POST'])
@token_required
def logout():
    """Logout endpoint (client-side token invalidation)"""
    try:
        current_user = get_current_user()
        logger.info(f"✅ User logged out: {current_user['email']}")
        
        return jsonify({'message': 'Logged out successfully'})
        
    except Exception as e:
        logger.error(f"Logout error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

# ------------------------
# Dashboard Endpoints
# ------------------------
@app.route('/api/dashboard/stats', methods=['GET'])
@token_required
def get_dashboard_stats():
    try:
        # Get basic counts
        stats = {
            'students': students.count_documents({}),
            'staff': staff.count_documents({}),
            'classes': classes.count_documents({}),
            'grades': grades.count_documents({}),
            'attendance_records': attendance.count_documents({})
        }
        
        # Calculate average grades per class
        class_stats = []
        for class_doc in classes.find():
            class_students = list(students.find({'class_id': class_doc['_id']}))
            student_ids = [s['_id'] for s in class_students]
            
            if student_ids:
                class_grades = list(grades.find({'student_id': {'$in': student_ids}}))
                if class_grades:
                    avg_grade = sum(g['grade'] for g in class_grades) / len(class_grades)
                else:
                    avg_grade = 0
                
                class_stats.append({
                    'class_id': class_doc['_id'],
                    'class_name': class_doc['name'],
                    'average_grade': round(avg_grade, 2),
                    'student_count': len(class_students),
                    'teacher_name': class_doc.get('class_teacher_name', 'Not assigned')
                })
        
        # Top performing students
        top_students = []
        all_students = list(students.find({'status': 'active'}).limit(20))
        
        for student in all_students:
            student_grades = list(grades.find({'student_id': student['_id']}))
            if student_grades:
                avg_grade = sum(g['grade'] for g in student_grades) / len(student_grades)
            else:
                avg_grade = 0
            
            # Get class name
            class_name = 'No Class'
            if student.get('class_id'):
                class_doc = classes.find_one({'_id': student['class_id']})
                if class_doc:
                    class_name = class_doc.get('name', 'Unknown')
            
            top_students.append({
                'student_id': student['_id'],
                'student_name': student['name'],
                'class': class_name,
                'class_id': student.get('class_id'),
                'average_grade': round(avg_grade, 2),
                'profile_picture': student.get('profile_picture')
            })
        
        # Sort by average grade
        top_students.sort(key=lambda x: x['average_grade'], reverse=True)
        
        # Recent activities from audit logs
        recent_activities = []
        audit_entries = list(audit_logs.find().sort('timestamp', DESCENDING).limit(10))
        
        for entry in audit_entries:
            # Get user name
            user = users.find_one({'_id': entry['user_id']})
            user_name = user.get('name', 'System') if user else 'System'
            
            # Determine icon based on action
            icon_map = {
                'create': 'user-plus',
                'update': 'edit',
                'delete': 'trash',
                'login': 'sign-in-alt',
                'logout': 'sign-out-alt',
                'add': 'plus-circle',
                'remove': 'minus-circle'
            }
            
            recent_activities.append({
                'id': entry['_id'],
                'title': f"{entry['action'].capitalize()} {entry['entity_type']}",
                'description': f"{user_name} {entry['action']}d {entry['entity_type']}",
                'icon': icon_map.get(entry['action'], 'bell'),
                'timestamp': entry['timestamp'],
                'user': user_name
            })
        
        # Calculate new students (admitted in current year)
        current_year = datetime.utcnow().year
        new_students_count = students.count_documents({'admission_year': current_year})
        
        # Calculate active staff
        active_staff_count = staff.count_documents({'status': 'active'})
        
        # Calculate average class size
        total_students = stats['students']
        total_classes = stats['classes']
        avg_class_size = total_students / total_classes if total_classes > 0 else 0
        
        # Calculate top grade
        if top_students:
            top_grade = max([s['average_grade'] for s in top_students])
        else:
            top_grade = 0
        
        # Extended stats for frontend
        extended_stats = {
            'new_students': new_students_count,
            'active_staff': active_staff_count,
            'avg_class_size': round(avg_class_size, 1),
            'top_grade': round(top_grade, 1),
            'avg_grade': round(sum([s['average_grade'] for s in top_students]) / len(top_students) if top_students else 0, 1)
        }
        
        return jsonify({
            'success': True,
            'stats': {**stats, **extended_stats},
            'class_statistics': class_stats,
            'top_students': top_students[:5],  # Top 5 only
            'recent_activity': recent_activities,
            'last_updated': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Dashboard stats error: {e}")
        logger.error(traceback.format_exc())
        return jsonify({'error': 'Failed to load dashboard statistics'}), 500

@app.route('/api/dashboard/top-students', methods=['GET'])
@token_required
def get_top_students():
    """Get top performing students"""
    try:
        limit = int(request.args.get('limit', 10))
        
        all_students = list(students.find({'status': 'active'}))
        student_scores = []
        
        for student in all_students:
            student_grades = list(grades.find({'student_id': student['_id']}))
            if student_grades:
                avg_grade = sum(g['grade'] for g in student_grades) / len(student_grades)
            else:
                avg_grade = 0
            
            # Get class name
            class_name = 'No Class'
            if student.get('class_id'):
                class_doc = classes.find_one({'_id': student['class_id']})
                if class_doc:
                    class_name = class_doc.get('name', 'Unknown')
            
            student_scores.append({
                'student_id': student['_id'],
                'student_name': student['name'],
                'class': class_name,
                'average_grade': round(avg_grade, 2),
                'profile_picture': student.get('profile_picture')
            })
        
        # Sort by average grade
        student_scores.sort(key=lambda x: x['average_grade'], reverse=True)
        
        return jsonify({
            'success': True,
            'top_students': student_scores[:limit]
        })
        
    except Exception as e:
        logger.error(f"Top students error: {e}")
        return jsonify({'error': 'Failed to load top students'}), 500

@app.route('/api/dashboard/recent-activity', methods=['GET'])
@token_required
def get_recent_activity():
    """Get recent system activities"""
    try:
        limit = int(request.args.get('limit', 20))
        
        activities = []
        audit_entries = list(audit_logs.find().sort('timestamp', DESCENDING).limit(limit))
        
        for entry in audit_entries:
            # Get user name
            user = users.find_one({'_id': entry['user_id']})
            user_name = user.get('name', 'System') if user else 'System'
            
            activities.append({
                'id': entry['_id'],
                'title': f"{entry['action'].capitalize()} {entry['entity_type']}",
                'description': f"{user_name} performed {entry['action']} on {entry['entity_type']}",
                'icon': 'bell',
                'timestamp': entry['timestamp'],
                'user': user_name
            })
        
        return jsonify({
            'success': True,
            'activities': activities
        })
        
    except Exception as e:
        logger.error(f"Recent activity error: {e}")
        return jsonify({'error': 'Failed to load recent activity'}), 500

# ------------------------
# Student Endpoints
# ------------------------
@app.route('/api/students', methods=['POST'])
@token_required
@role_required('admin', 'teacher')
def add_student():
    try:
        require_json()
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['name', 'class_id', 'admission_year']
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            return jsonify({'error': f'Missing required fields: {", ".join(missing_fields)}'}), 400
        
        # Generate student ID
        year_prefix = str(data['admission_year'])[-2:]
        student_count = students.count_documents({'admission_year': data['admission_year']}) + 1
        student_id = f"STU-{year_prefix}-{student_count:04d}"
        
        # Get class details
        class_doc = classes.find_one({'_id': data['class_id']})
        if not class_doc:
            return jsonify({'error': 'Class not found'}), 404
        
        # Prepare student data
        student = {
            '_id': student_id,
            'name': data['name'].strip(),
            'gender': data.get('gender', 'Not specified'),
            'date_of_birth': data.get('date_of_birth'),
            'class_id': data['class_id'],
            'class_name': class_doc.get('name'),
            'admission_year': int(data['admission_year']),
            'parent_contact': data.get('parent_contact', ''),
            'parent_name': data.get('parent_name', ''),
            'parent_email': data.get('parent_email', ''),
            'address': data.get('address', ''),
            'district': data.get('district', 'Kampala'),
            'bio': data.get('bio', ''),
            'hobbies': data.get('hobbies', []),
            'profile_picture': data.get('profile_picture'),
            'status': 'active',
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow(),
            'created_by': get_current_user()['_id']
        }
        
        # Insert student
        result = students.insert_one(student)
        
        # Update class student count
        classes.update_one(
            {'_id': data['class_id']},
            {'$inc': {'student_count': 1}}
        )
        
        # Log the action
        log_audit('create', 'student', student_id, student)
        
        logger.info(f"✅ Student added: {student['name']} (ID: {student_id})")
        
        return jsonify({
            'success': True,
            'message': 'Student added successfully',
            'student': serialize_document(student),
            'student_id': student_id
        }), 201
        
    except Exception as e:
        logger.error(f"Add student error: {e}")
        logger.error(traceback.format_exc())
        return jsonify({'error': 'Failed to add student'}), 500

@app.route('/api/students', methods=['GET'])
@token_required
def get_students():
    try:
        # Build query based on filters
        query = {}
        
        # Search by name or ID
        if 'search' in request.args:
            search_term = request.args['search'].strip()
            if search_term:
                query['$or'] = [
                    {'name': {'$regex': search_term, '$options': 'i'}},
                    {'_id': {'$regex': search_term, '$options': 'i'}},
                    {'parent_contact': {'$regex': search_term, '$options': 'i'}},
                    {'parent_email': {'$regex': search_term, '$options': 'i'}}
                ]
        
        # Filter by class
        if 'class_id' in request.args:
            class_id = request.args['class_id'].strip()
            if class_id:
                query['class_id'] = class_id
        
        # Filter by admission year
        if 'admission_year' in request.args:
            try:
                query['admission_year'] = int(request.args['admission_year'])
            except ValueError:
                pass
        
        # Filter by status
        if 'status' in request.args:
            status = request.args['status'].strip()
            if status:
                query['status'] = status
        
        # Pagination
        page = max(1, int(request.args.get('page', 1)))
        per_page = min(100, max(1, int(request.args.get('per_page', 20))))
        skip = (page - 1) * per_page
        
        # Sorting
        sort_field = request.args.get('sort', 'name')
        sort_direction = ASCENDING if request.args.get('order', 'asc') == 'asc' else DESCENDING
        sort_option = [(sort_field, sort_direction)]
        
        # Get students
        students_list = list(students.find(query).sort(sort_option).skip(skip).limit(per_page))
        total = students.count_documents(query)
        
        # Calculate performance for each student
        for student in students_list:
            student_grades = list(grades.find({'student_id': student['_id']}))
            if student_grades:
                avg_grade = sum(g['grade'] for g in student_grades) / len(student_grades)
                student['average_grade'] = round(avg_grade, 2)
                student['highest_grade'] = max(g['grade'] for g in student_grades)
                student['lowest_grade'] = min(g['grade'] for g in student_grades)
                student['grade_count'] = len(student_grades)
            else:
                student['average_grade'] = 0
                student['highest_grade'] = 0
                student['lowest_grade'] = 0
                student['grade_count'] = 0
        
        return jsonify({
            'success': True,
            'students': [serialize_document(s) for s in students_list],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total,
                'pages': (total + per_page - 1) // per_page,
                'has_next': page * per_page < total,
                'has_prev': page > 1
            }
        })
        
    except Exception as e:
        logger.error(f"Get students error: {e}")
        logger.error(traceback.format_exc())
        return jsonify({'error': 'Failed to load students'}), 500

@app.route('/api/students/<student_id>', methods=['GET'])
@token_required
def get_student(student_id):
    try:
        student = students.find_one({'_id': student_id})
        if not student:
            return jsonify({'error': 'Student not found'}), 404
        
        # Get class details
        class_info = None
        if student.get('class_id'):
            class_info = classes.find_one({'_id': student['class_id']})
        
        # Get attendance records (last 30 days)
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        attendance_records = list(attendance.find({
            'student_id': student_id,
            'timestamp': {'$gte': thirty_days_ago}
        }).sort('date', DESCENDING))
        
        # Get grades
        student_grades = list(grades.find({'student_id': student_id}).sort('entered_at', DESCENDING))
        
        # Calculate performance
        if student_grades:
            grades_list = [g['grade'] for g in student_grades]
            performance = {
                'average': round(sum(grades_list) / len(grades_list), 2),
                'highest': max(grades_list),
                'lowest': min(grades_list),
                'total_subjects': len(set(g['subject'] for g in student_grades)),
                'total_grades': len(student_grades)
            }
            
            # Group grades by subject
            subject_grades = {}
            for grade in student_grades:
                subject = grade['subject']
                if subject not in subject_grades:
                    subject_grades[subject] = []
                subject_grades[subject].append(grade['grade'])
            
            subject_stats = []
            for subject, grades_list in subject_grades.items():
                subject_stats.append({
                    'subject': subject,
                    'average': round(sum(grades_list) / len(grades_list), 2),
                    'highest': max(grades_list),
                    'lowest': min(grades_list),
                    'count': len(grades_list)
                })
        else:
            performance = {
                'average': 0,
                'highest': 0,
                'lowest': 0,
                'total_subjects': 0,
                'total_grades': 0
            }
            subject_stats = []
        
        # Calculate attendance percentage
        if attendance_records:
            present_count = sum(1 for r in attendance_records if r['status'] == 'present')
            attendance_percentage = (present_count / len(attendance_records)) * 100
        else:
            attendance_percentage = 0
        
        student_data = serialize_document(student)
        student_data['class_info'] = serialize_document(class_info) if class_info else None
        student_data['attendance'] = [serialize_document(r) for r in attendance_records]
        student_data['grades'] = [serialize_document(g) for g in student_grades]
        student_data['performance'] = performance
        student_data['subject_statistics'] = subject_stats
        student_data['attendance_percentage'] = round(attendance_percentage, 1)
        
        return jsonify({
            'success': True,
            'student': student_data
        })
        
    except Exception as e:
        logger.error(f"Get student error: {e}")
        logger.error(traceback.format_exc())
        return jsonify({'error': 'Failed to load student details'}), 500

@app.route('/api/students/<student_id>', methods=['PUT'])
@token_required
@role_required('admin', 'teacher')
def update_student(student_id):
    try:
        require_json()
        data = request.get_json()
        
        student = students.find_one({'_id': student_id})
        if not student:
            return jsonify({'error': 'Student not found'}), 404
        
        # Track changes for audit
        changes = {}
        update_data = {}
        
        # Update fields
        updatable_fields = [
            'name', 'gender', 'date_of_birth', 'class_id', 'admission_year',
            'parent_contact', 'parent_name', 'parent_email', 'address',
            'district', 'bio', 'hobbies', 'profile_picture', 'status'
        ]
        
        for field in updatable_fields:
            if field in data:
                old_value = student.get(field)
                new_value = data[field]
                
                if old_value != new_value:
                    changes[field] = {'old': old_value, 'new': new_value}
                    update_data[field] = new_value
        
        # If class changed, update class student counts
        if 'class_id' in changes:
            old_class_id = changes['class_id']['old']
            new_class_id = changes['class_id']['new']
            
            # Decrement old class count
            if old_class_id:
                classes.update_one(
                    {'_id': old_class_id},
                    {'$inc': {'student_count': -1}}
                )
            
            # Increment new class count
            if new_class_id:
                classes.update_one(
                    {'_id': new_class_id},
                    {'$inc': {'student_count': 1}}
                )
                
                # Get new class name
                new_class = classes.find_one({'_id': new_class_id})
                if new_class:
                    update_data['class_name'] = new_class.get('name')
        
        if not update_data:
            return jsonify({'error': 'No changes provided'}), 400
        
        update_data['updated_at'] = datetime.utcnow()
        
        # Perform update
        result = students.update_one(
            {'_id': student_id},
            {'$set': update_data}
        )
        
        if result.modified_count == 0:
            return jsonify({'error': 'No changes made'}), 400
        
        # Log changes
        if changes:
            log_audit('update', 'student', student_id, changes)
        
        logger.info(f"✅ Student updated: {student_id}")
        
        return jsonify({
            'success': True,
            'message': 'Student updated successfully',
            'changes': changes
        })
        
    except Exception as e:
        logger.error(f"Update student error: {e}")
        logger.error(traceback.format_exc())
        return jsonify({'error': 'Failed to update student'}), 500

@app.route('/api/students/<student_id>', methods=['DELETE'])
@token_required
@role_required('admin')
def delete_student(student_id):
    try:
        student = students.find_one({'_id': student_id})
        if not student:
            return jsonify({'error': 'Student not found'}), 404
        
        # Store student data for audit
        student_data = serialize_document(student)
        
        # Delete student
        result = students.delete_one({'_id': student_id})
        
        if result.deleted_count == 0:
            return jsonify({'error': 'Failed to delete student'}), 500
        
        # Update class student count
        if student.get('class_id'):
            classes.update_one(
                {'_id': student['class_id']},
                {'$inc': {'student_count': -1}}
            )
        
        # Delete related grades
        grades.delete_many({'student_id': student_id})
        
        # Delete related attendance
        attendance.delete_many({'student_id': student_id})
        
        # Log the action
        log_audit('delete', 'student', student_id, {'student_data': student_data})
        
        logger.info(f"✅ Student deleted: {student['name']} (ID: {student_id})")
        
        return jsonify({
            'success': True,
            'message': 'Student deleted successfully'
        })
        
    except Exception as e:
        logger.error(f"Delete student error: {e}")
        logger.error(traceback.format_exc())
        return jsonify({'error': 'Failed to delete student'}), 500

@app.route('/api/students/<student_id>/grades', methods=['GET'])
@token_required
def get_student_grades(student_id):
    """Get all grades for a specific student"""
    try:
        student = students.find_one({'_id': student_id})
        if not student:
            return jsonify({'error': 'Student not found'}), 404
        
        # Get grades with optional filters
        query = {'student_id': student_id}
        
        if 'subject' in request.args:
            query['subject'] = request.args['subject']
        
        if 'term' in request.args:
            query['term'] = int(request.args['term'])
        
        if 'academic_year' in request.args:
            query['academic_year'] = int(request.args['academic_year'])
        
        student_grades = list(grades.find(query).sort([('academic_year', DESCENDING), ('term', DESCENDING)]))
        
        # Calculate statistics
        if student_grades:
            grades_list = [g['grade'] for g in student_grades]
            performance = {
                'average': round(sum(grades_list) / len(grades_list), 2),
                'highest': max(grades_list),
                'lowest': min(grades_list),
                'total_grades': len(student_grades),
                'total_subjects': len(set(g['subject'] for g in student_grades))
            }
            
            # Group by subject
            subject_stats = {}
            for grade in student_grades:
                subject = grade['subject']
                if subject not in subject_stats:
                    subject_stats[subject] = []
                subject_stats[subject].append(grade['grade'])
            
            subject_performance = []
            for subject, grade_list in subject_stats.items():
                subject_performance.append({
                    'subject': subject,
                    'average': round(sum(grade_list) / len(grade_list), 2),
                    'highest': max(grade_list),
                    'lowest': min(grade_list),
                    'count': len(grade_list)
                })
        else:
            performance = {
                'average': 0,
                'highest': 0,
                'lowest': 0,
                'total_grades': 0,
                'total_subjects': 0
            }
            subject_performance = []
        
        return jsonify({
            'success': True,
            'student': {
                '_id': student['_id'],
                'name': student['name'],
                'class_id': student.get('class_id'),
                'class_name': student.get('class_name')
            },
            'grades': [serialize_document(g) for g in student_grades],
            'performance': performance,
            'subject_statistics': subject_performance
        })
        
    except Exception as e:
        logger.error(f"Get student grades error: {e}")
        return jsonify({'error': 'Failed to load student grades'}), 500

@app.route('/api/students/<student_id>/attendance', methods=['GET'])
@token_required
def get_student_attendance(student_id):
    """Get attendance records for a specific student"""
    try:
        student = students.find_one({'_id': student_id})
        if not student:
            return jsonify({'error': 'Student not found'}), 404
        
        # Date range filters
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        query = {'student_id': student_id}
        
        if start_date:
            try:
                start_dt = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
                query['date'] = {'$gte': start_dt}
            except ValueError:
                pass
        
        if end_date:
            try:
                end_dt = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
                if 'date' in query:
                    query['date']['$lte'] = end_dt
                else:
                    query['date'] = {'$lte': end_dt}
            except ValueError:
                pass
        
        attendance_records = list(attendance.find(query).sort('date', DESCENDING))
        
        # Calculate attendance statistics
        if attendance_records:
            status_counts = {}
            for record in attendance_records:
                status = record['status']
                status_counts[status] = status_counts.get(status, 0) + 1
            
            total_records = len(attendance_records)
            present_count = status_counts.get('present', 0)
            attendance_percentage = (present_count / total_records) * 100 if total_records > 0 else 0
            
            statistics = {
                'total_records': total_records,
                'present': status_counts.get('present', 0),
                'absent': status_counts.get('absent', 0),
                'late': status_counts.get('late', 0),
                'excused': status_counts.get('excused', 0),
                'attendance_percentage': round(attendance_percentage, 1)
            }
        else:
            statistics = {
                'total_records': 0,
                'present': 0,
                'absent': 0,
                'late': 0,
                'excused': 0,
                'attendance_percentage': 0
            }
        
        return jsonify({
            'success': True,
            'student': {
                '_id': student['_id'],
                'name': student['name']
            },
            'attendance': [serialize_document(r) for r in attendance_records],
            'statistics': statistics
        })
        
    except Exception as e:
        logger.error(f"Get student attendance error: {e}")
        return jsonify({'error': 'Failed to load student attendance'}), 500

@app.route('/api/students/<student_id>/attendance', methods=['POST'])
@token_required
@role_required('admin', 'teacher')
def mark_attendance(student_id):
    """Mark attendance for a student"""
    try:
        require_json()
        data = request.get_json()
        
        student = students.find_one({'_id': student_id})
        if not student:
            return jsonify({'error': 'Student not found'}), 404
        
        # Validate required fields
        if 'status' not in data:
            return jsonify({'error': 'Attendance status is required'}), 400
        
        valid_statuses = ['present', 'absent', 'late', 'excused']
        if data['status'] not in valid_statuses:
            return jsonify({'error': f'Invalid status. Must be one of: {", ".join(valid_statuses)}'}), 400
        
        # Use provided date or current date
        if 'date' in data:
            try:
                date_obj = datetime.fromisoformat(data['date'].replace('Z', '+00:00'))
            except ValueError:
                return jsonify({'error': 'Invalid date format. Use ISO format (YYYY-MM-DD)'}), 400
        else:
            date_obj = datetime.utcnow()
        
        # Check if attendance already marked for this date
        existing_attendance = attendance.find_one({
            'student_id': student_id,
            'date': {'$gte': date_obj.replace(hour=0, minute=0, second=0, microsecond=0),
                    '$lt': date_obj.replace(hour=23, minute=59, second=59, microsecond=999999)}
        })
        
        attendance_record = {
            '_id': str(uuid.uuid4()),
            'student_id': student_id,
            'student_name': student['name'],
            'date': date_obj,
            'status': data['status'],
            'class_id': student.get('class_id'),
            'class_name': student.get('class_name'),
            'marked_by': get_current_user()['_id'],
            'marked_by_name': get_current_user().get('name'),
            'notes': data.get('notes', ''),
            'timestamp': datetime.utcnow()
        }
        
        if existing_attendance:
            # Update existing record
            result = attendance.update_one(
                {'_id': existing_attendance['_id']},
                {'$set': attendance_record}
            )
            action = 'updated'
        else:
            # Insert new record
            attendance.insert_one(attendance_record)
            action = 'marked'
        
        logger.info(f"✅ Attendance {action} for student: {student['name']} - {data['status']}")
        
        return jsonify({
            'success': True,
            'message': f'Attendance {action} successfully',
            'attendance': serialize_document(attendance_record)
        }), 201 if not existing_attendance else 200
        
    except Exception as e:
        logger.error(f"Mark attendance error: {e}")
        return jsonify({'error': 'Failed to mark attendance'}), 500

@app.route('/api/students/<student_id>/audit', methods=['GET'])
@token_required
@role_required('admin')
def get_student_audit(student_id):
    """Get audit logs for a specific student"""
    try:
        student = students.find_one({'_id': student_id})
        if not student:
            return jsonify({'error': 'Student not found'}), 404
        
        audit_logs_list = list(audit_logs.find(
            {'entity_id': student_id, 'entity_type': 'student'}
        ).sort('timestamp', DESCENDING))
        
        return jsonify({
            'success': True,
            'audit_logs': [serialize_document(log) for log in audit_logs_list]
        })
        
    except Exception as e:
        logger.error(f"Get student audit error: {e}")
        return jsonify({'error': 'Failed to load audit logs'}), 500

# ------------------------
# Staff Endpoints
# ------------------------
@app.route('/api/staff', methods=['POST'])
@token_required
@role_required('admin')
def add_staff():
    try:
        require_json()
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['name', 'email', 'role', 'department']
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            return jsonify({'error': f'Missing required fields: {", ".join(missing_fields)}'}), 400
        
        # Validate email
        if not validate_email(data['email']):
            return jsonify({'error': 'Invalid email format'}), 400
        
        # Validate role
        valid_roles = ['teacher', 'administrator', 'support', 'admin']
        if data['role'] not in valid_roles:
            return jsonify({'error': f'Invalid role. Must be one of: {", ".join(valid_roles)}'}), 400
        
        # Check if staff with email exists
        if staff.find_one({'email': data['email']}):
            return jsonify({'error': 'Staff member with this email already exists'}), 409
        
        # Generate staff ID
        staff_id = f"STAFF-{str(uuid.uuid4())[:8].upper()}"
        
        staff_member = {
            '_id': staff_id,
            'name': data['name'].strip(),
            'email': data['email'].lower().strip(),
            'phone': data.get('phone', ''),
            'role': data['role'],
            'department': data['department'].strip(),
            'subjects': data.get('subjects', []),
            'classes_taught': data.get('classes_taught', []),
            'qualifications': data.get('qualifications', []),
            'employment_date': data.get('employment_date', datetime.utcnow().date().isoformat()),
            'bio': data.get('bio', ''),
            'profile_picture': data.get('profile_picture'),
            'address': data.get('address', ''),
            'district': data.get('district', 'Kampala'),
            'status': 'active',
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow(),
            'created_by': get_current_user()['_id']
        }
        
        staff.insert_one(staff_member)
        
        # Log the action
        log_audit('create', 'staff', staff_id, staff_member)
        
        logger.info(f"✅ Staff member added: {staff_member['name']} (ID: {staff_id})")
        
        return jsonify({
            'success': True,
            'message': 'Staff member added successfully',
            'staff': serialize_document(staff_member)
        }), 201
        
    except Exception as e:
        logger.error(f"Add staff error: {e}")
        logger.error(traceback.format_exc())
        return jsonify({'error': 'Failed to add staff member'}), 500

@app.route('/api/staff', methods=['GET'])
@token_required
def get_staff_list():
    try:
        # Build query based on filters
        query = {}
        
        # Search by name, email, or department
        if 'search' in request.args:
            search_term = request.args['search'].strip()
            if search_term:
                query['$or'] = [
                    {'name': {'$regex': search_term, '$options': 'i'}},
                    {'email': {'$regex': search_term, '$options': 'i'}},
                    {'department': {'$regex': search_term, '$options': 'i'}},
                    {'phone': {'$regex': search_term, '$options': 'i'}}
                ]
        
        # Filter by department
        if 'department' in request.args:
            department = request.args['department'].strip()
            if department:
                query['department'] = department
        
        # Filter by role
        if 'role' in request.args:
            role = request.args['role'].strip()
            if role:
                query['role'] = role
        
        # Filter by status
        if 'status' in request.args:
            status = request.args['status'].strip()
            if status:
                query['status'] = status
        
        # Pagination
        page = max(1, int(request.args.get('page', 1)))
        per_page = min(100, max(1, int(request.args.get('per_page', 20))))
        skip = (page - 1) * per_page
        
        # Sorting
        sort_field = request.args.get('sort', 'name')
        sort_direction = ASCENDING if request.args.get('order', 'asc') == 'asc' else DESCENDING
        sort_option = [(sort_field, sort_direction)]
        
        # Get staff
        staff_list = list(staff.find(query).sort(sort_option).skip(skip).limit(per_page))
        total = staff.count_documents(query)
        
        return jsonify({
            'success': True,
            'staff': [serialize_document(s) for s in staff_list],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total,
                'pages': (total + per_page - 1) // per_page
            }
        })
        
    except Exception as e:
        logger.error(f"Get staff list error: {e}")
        logger.error(traceback.format_exc())
        return jsonify({'error': 'Failed to load staff list'}), 500

@app.route('/api/staff/<staff_id>', methods=['GET'])
@token_required
def get_staff_member(staff_id):
    try:
        staff_member = staff.find_one({'_id': staff_id})
        if not staff_member:
            return jsonify({'error': 'Staff member not found'}), 404
        
        # Get classes taught by this staff member
        classes_taught = []
        if staff_member.get('classes_taught'):
            classes_taught = list(classes.find({'_id': {'$in': staff_member['classes_taught']}}))
        
        staff_data = serialize_document(staff_member)
        staff_data['classes_taught_details'] = [serialize_document(c) for c in classes_taught]
        
        return jsonify({
            'success': True,
            'staff': staff_data
        })
        
    except Exception as e:
        logger.error(f"Get staff member error: {e}")
        return jsonify({'error': 'Failed to load staff member details'}), 500

@app.route('/api/staff/<staff_id>', methods=['PUT'])
@token_required
@role_required('admin')
def update_staff(staff_id):
    try:
        require_json()
        data = request.get_json()
        
        staff_member = staff.find_one({'_id': staff_id})
        if not staff_member:
            return jsonify({'error': 'Staff member not found'}), 404
        
        # Track changes for audit
        changes = {}
        update_data = {}
        
        # Update fields
        updatable_fields = [
            'name', 'email', 'phone', 'role', 'department', 'subjects',
            'classes_taught', 'qualifications', 'employment_date', 'bio',
            'profile_picture', 'address', 'district', 'status'
        ]
        
        for field in updatable_fields:
            if field in data:
                old_value = staff_member.get(field)
                new_value = data[field]
                
                if old_value != new_value:
                    changes[field] = {'old': old_value, 'new': new_value}
                    update_data[field] = new_value
        
        if not update_data:
            return jsonify({'error': 'No changes provided'}), 400
        
        update_data['updated_at'] = datetime.utcnow()
        
        # Perform update
        result = staff.update_one(
            {'_id': staff_id},
            {'$set': update_data}
        )
        
        if result.modified_count == 0:
            return jsonify({'error': 'No changes made'}), 400
        
        # Log changes
        if changes:
            log_audit('update', 'staff', staff_id, changes)
        
        logger.info(f"✅ Staff member updated: {staff_id}")
        
        return jsonify({
            'success': True,
            'message': 'Staff member updated successfully',
            'changes': changes
        })
        
    except Exception as e:
        logger.error(f"Update staff error: {e}")
        logger.error(traceback.format_exc())
        return jsonify({'error': 'Failed to update staff member'}), 500

@app.route('/api/staff/<staff_id>', methods=['DELETE'])
@token_required
@role_required('admin')
def delete_staff(staff_id):
    try:
        staff_member = staff.find_one({'_id': staff_id})
        if not staff_member:
            return jsonify({'error': 'Staff member not found'}), 404
        
        # Store staff data for audit
        staff_data = serialize_document(staff_member)
        
        # Delete staff member
        result = staff.delete_one({'_id': staff_id})
        
        if result.deleted_count == 0:
            return jsonify({'error': 'Failed to delete staff member'}), 500
        
        # Remove from classes as teacher
        classes.update_many(
            {'class_teacher_id': staff_id},
            {'$set': {
                'class_teacher_id': None,
                'class_teacher_name': None
            }}
        )
        
        # Log the action
        log_audit('delete', 'staff', staff_id, {'staff_data': staff_data})
        
        logger.info(f"✅ Staff member deleted: {staff_member['name']} (ID: {staff_id})")
        
        return jsonify({
            'success': True,
            'message': 'Staff member deleted successfully'
        })
        
    except Exception as e:
        logger.error(f"Delete staff error: {e}")
        logger.error(traceback.format_exc())
        return jsonify({'error': 'Failed to delete staff member'}), 500

# ------------------------
# Class Endpoints
# ------------------------
@app.route('/api/classes', methods=['POST'])
@token_required
@role_required('admin')
def add_class():
    try:
        require_json()
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['name', 'level']
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            return jsonify({'error': f'Missing required fields: {", ".join(missing_fields)}'}), 400
        
        # Generate class ID
        class_id = f"CLASS-{str(uuid.uuid4())[:8].upper()}"
        
        # Get teacher details if provided
        teacher_name = None
        if data.get('class_teacher_id'):
            teacher = staff.find_one({'_id': data['class_teacher_id']})
            if teacher:
                teacher_name = teacher.get('name')
        
        class_doc = {
            '_id': class_id,
            'name': data['name'].strip(),
            'level': data['level'].strip(),
            'stream': data.get('stream', ''),
            'academic_year': data.get('academic_year', datetime.utcnow().year),
            'class_teacher_id': data.get('class_teacher_id'),
            'class_teacher_name': teacher_name,
            'schedule': data.get('schedule', []),
            'capacity': data.get('capacity', 40),
            'room_number': data.get('room_number', ''),
            'subjects': data.get('subjects', []),
            'student_count': 0,
            'average_grade': 0,
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow(),
            'created_by': get_current_user()['_id']
        }
        
        classes.insert_one(class_doc)
        
        # Update teacher's classes_taught if teacher assigned
        if data.get('class_teacher_id'):
            staff.update_one(
                {'_id': data['class_teacher_id']},
                {'$addToSet': {'classes_taught': class_id}}
            )
        
        # Log the action
        log_audit('create', 'class', class_id, class_doc)
        
        logger.info(f"✅ Class created: {class_doc['name']} (ID: {class_id})")
        
        return jsonify({
            'success': True,
            'message': 'Class created successfully',
            'class': serialize_document(class_doc)
        }), 201
        
    except Exception as e:
        logger.error(f"Add class error: {e}")
        logger.error(traceback.format_exc())
        return jsonify({'error': 'Failed to create class'}), 500

@app.route('/api/classes', methods=['GET'])
@token_required
def get_classes():
    try:
        # Build query based on filters
        query = {}
        
        # Search by name, level, or stream
        if 'search' in request.args:
            search_term = request.args['search'].strip()
            if search_term:
                query['$or'] = [
                    {'name': {'$regex': search_term, '$options': 'i'}},
                    {'level': {'$regex': search_term, '$options': 'i'}},
                    {'stream': {'$regex': search_term, '$options': 'i'}},
                    {'room_number': {'$regex': search_term, '$options': 'i'}}
                ]
        
        # Filter by level
        if 'level' in request.args:
            level = request.args['level'].strip()
            if level:
                query['level'] = level
        
        # Filter by academic year
        if 'academic_year' in request.args:
            try:
                query['academic_year'] = int(request.args['academic_year'])
            except ValueError:
                pass
        
        # Filter by teacher
        if 'teacher_id' in request.args:
            teacher_id = request.args['teacher_id'].strip()
            if teacher_id:
                query['class_teacher_id'] = teacher_id
        
        # Pagination
        page = max(1, int(request.args.get('page', 1)))
        per_page = min(100, max(1, int(request.args.get('per_page', 20))))
        skip = (page - 1) * per_page
        
        # Sorting
        sort_field = request.args.get('sort', 'name')
        sort_direction = ASCENDING if request.args.get('order', 'asc') == 'asc' else DESCENDING
        sort_option = [(sort_field, sort_direction)]
        
        # Get classes
        classes_list = list(classes.find(query).sort(sort_option).skip(skip).limit(per_page))
        total = classes.count_documents(query)
        
        # Calculate average grade for each class
        for class_doc in classes_list:
            class_students = list(students.find({'class_id': class_doc['_id']}))
            student_ids = [s['_id'] for s in class_students]
            
            if student_ids:
                class_grades = list(grades.find({'student_id': {'$in': student_ids}}))
                if class_grades:
                    avg_grade = sum(g['grade'] for g in class_grades) / len(class_grades)
                    class_doc['average_grade'] = round(avg_grade, 2)
                else:
                    class_doc['average_grade'] = 0
            else:
                class_doc['average_grade'] = 0
        
        return jsonify({
            'success': True,
            'classes': [serialize_document(c) for c in classes_list],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total,
                'pages': (total + per_page - 1) // per_page
            }
        })
        
    except Exception as e:
        logger.error(f"Get classes error: {e}")
        logger.error(traceback.format_exc())
        return jsonify({'error': 'Failed to load classes'}), 500

@app.route('/api/classes/<class_id>', methods=['GET'])
@token_required
def get_class(class_id):
    try:
        class_doc = classes.find_one({'_id': class_id})
        if not class_doc:
            return jsonify({'error': 'Class not found'}), 404
        
        # Get class teacher details
        teacher_info = None
        if class_doc.get('class_teacher_id'):
            teacher_info = staff.find_one({'_id': class_doc['class_teacher_id']})
        
        # Get students in this class
        class_students = list(students.find({'class_id': class_id}))
        
        # Get class grades
        student_ids = [s['_id'] for s in class_students]
        class_grades = list(grades.find({'student_id': {'$in': student_ids}}))
        
        # Calculate class statistics
        if class_grades:
            grades_list = [g['grade'] for g in class_grades]
            class_stats = {
                'average_grade': round(sum(grades_list) / len(grades_list), 2),
                'highest_grade': max(grades_list),
                'lowest_grade': min(grades_list),
                'total_grades': len(class_grades)
            }
            
            # Group grades by subject
            subject_grades = {}
            for grade in class_grades:
                subject = grade['subject']
                if subject not in subject_grades:
                    subject_grades[subject] = []
                subject_grades[subject].append(grade['grade'])
            
            subject_stats = []
            for subject, grades_list in subject_grades.items():
                subject_stats.append({
                    'subject': subject,
                    'average': round(sum(grades_list) / len(grades_list), 2),
                    'highest': max(grades_list),
                    'lowest': min(grades_list),
                    'student_count': len(set(g['student_id'] for g in class_grades if g['subject'] == subject))
                })
        else:
            class_stats = {
                'average_grade': 0,
                'highest_grade': 0,
                'lowest_grade': 0,
                'total_grades': 0
            }
            subject_stats = []
        
        class_data = serialize_document(class_doc)
        class_data['teacher_info'] = serialize_document(teacher_info) if teacher_info else None
        class_data['students'] = [serialize_document(s) for s in class_students]
        class_data['statistics'] = class_stats
        class_data['subject_statistics'] = subject_stats
        
        return jsonify({
            'success': True,
            'class': class_data
        })
        
    except Exception as e:
        logger.error(f"Get class error: {e}")
        return jsonify({'error': 'Failed to load class details'}), 500

@app.route('/api/classes/<class_id>/students', methods=['GET'])
@token_required
def get_class_students(class_id):
    try:
        class_doc = classes.find_one({'_id': class_id})
        if not class_doc:
            return jsonify({'error': 'Class not found'}), 404
        
        # Get students with pagination
        page = max(1, int(request.args.get('page', 1)))
        per_page = min(100, max(1, int(request.args.get('per_page', 50))))
        skip = (page - 1) * per_page
        
        class_students = list(students.find({'class_id': class_id}).skip(skip).limit(per_page))
        total = students.count_documents({'class_id': class_id})
        
        # Calculate performance for each student
        for student in class_students:
            student_grades = list(grades.find({'student_id': student['_id']}))
            if student_grades:
                avg_grade = sum(g['grade'] for g in student_grades) / len(student_grades)
                student['average_grade'] = round(avg_grade, 2)
                student['grade_count'] = len(student_grades)
            else:
                student['average_grade'] = 0
                student['grade_count'] = 0
        
        return jsonify({
            'success': True,
            'class': serialize_document(class_doc),
            'students': [serialize_document(s) for s in class_students],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total,
                'pages': (total + per_page - 1) // per_page
            }
        })
        
    except Exception as e:
        logger.error(f"Get class students error: {e}")
        return jsonify({'error': 'Failed to load class students'}), 500

@app.route('/api/classes/<class_id>', methods=['PUT'])
@token_required
@role_required('admin')
def update_class(class_id):
    try:
        require_json()
        data = request.get_json()
        
        class_doc = classes.find_one({'_id': class_id})
        if not class_doc:
            return jsonify({'error': 'Class not found'}), 404
        
        # Track changes for audit
        changes = {}
        update_data = {}
        
        # Update fields
        updatable_fields = [
            'name', 'level', 'stream', 'academic_year', 'class_teacher_id',
            'capacity', 'room_number', 'subjects', 'schedule'
        ]
        
        for field in updatable_fields:
            if field in data:
                old_value = class_doc.get(field)
                new_value = data[field]
                
                if old_value != new_value:
                    changes[field] = {'old': old_value, 'new': new_value}
                    update_data[field] = new_value
        
        # Handle teacher assignment changes
        if 'class_teacher_id' in changes:
            old_teacher_id = changes['class_teacher_id']['old']
            new_teacher_id = changes['class_teacher_id']['new']
            
            # Remove class from old teacher's classes_taught
            if old_teacher_id:
                staff.update_one(
                    {'_id': old_teacher_id},
                    {'$pull': {'classes_taught': class_id}}
                )
            
            # Add class to new teacher's classes_taught and get teacher name
            if new_teacher_id:
                staff.update_one(
                    {'_id': new_teacher_id},
                    {'$addToSet': {'classes_taught': class_id}}
                )
                
                teacher = staff.find_one({'_id': new_teacher_id})
                if teacher:
                    update_data['class_teacher_name'] = teacher.get('name')
            else:
                update_data['class_teacher_name'] = None
        
        if not update_data:
            return jsonify({'error': 'No changes provided'}), 400
        
        update_data['updated_at'] = datetime.utcnow()
        
        # Perform update
        result = classes.update_one(
            {'_id': class_id},
            {'$set': update_data}
        )
        
        if result.modified_count == 0:
            return jsonify({'error': 'No changes made'}), 400
        
        # Log changes
        if changes:
            log_audit('update', 'class', class_id, changes)
        
        logger.info(f"✅ Class updated: {class_id}")
        
        return jsonify({
            'success': True,
            'message': 'Class updated successfully',
            'changes': changes
        })
        
    except Exception as e:
        logger.error(f"Update class error: {e}")
        logger.error(traceback.format_exc())
        return jsonify({'error': 'Failed to update class'}), 500

@app.route('/api/classes/<class_id>', methods=['DELETE'])
@token_required
@role_required('admin')
def delete_class(class_id):
    try:
        class_doc = classes.find_one({'_id': class_id})
        if not class_doc:
            return jsonify({'error': 'Class not found'}), 404
        
        # Check if class has students
        student_count = students.count_documents({'class_id': class_id})
        if student_count > 0:
            return jsonify({'error': 'Cannot delete class with students. Move students to another class first.'}), 400
        
        # Store class data for audit
        class_data = serialize_document(class_doc)
        
        # Delete class
        result = classes.delete_one({'_id': class_id})
        
        if result.deleted_count == 0:
            return jsonify({'error': 'Failed to delete class'}), 500
        
        # Remove class from teacher's classes_taught
        if class_doc.get('class_teacher_id'):
            staff.update_one(
                {'_id': class_doc['class_teacher_id']},
                {'$pull': {'classes_taught': class_id}}
            )
        
        # Log the action
        log_audit('delete', 'class', class_id, {'class_data': class_data})
        
        logger.info(f"✅ Class deleted: {class_doc['name']} (ID: {class_id})")
        
        return jsonify({
            'success': True,
            'message': 'Class deleted successfully'
        })
        
    except Exception as e:
        logger.error(f"Delete class error: {e}")
        logger.error(traceback.format_exc())
        return jsonify({'error': 'Failed to delete class'}), 500

# ------------------------
# Grade Endpoints
# ------------------------
@app.route('/api/grades', methods=['POST'])
@token_required
@role_required('admin', 'teacher')
def add_grade():
    try:
        require_json()
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['student_id', 'subject', 'grade']
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            return jsonify({'error': f'Missing required fields: {", ".join(missing_fields)}'}), 400
        
        # Validate grade value
        try:
            grade_value = float(data['grade'])
            if not (0 <= grade_value <= 100):
                return jsonify({'error': 'Grade must be between 0 and 100'}), 400
        except ValueError:
            return jsonify({'error': 'Grade must be a number'}), 400
        
        # Get student details
        student = students.find_one({'_id': data['student_id']})
        if not student:
            return jsonify({'error': 'Student not found'}), 404
        
        # Generate grade ID
        grade_id = str(uuid.uuid4())
        
        grade = {
            '_id': grade_id,
            'student_id': data['student_id'],
            'student_name': student['name'],
            'subject': data['subject'].strip(),
            'grade': grade_value,
            'max_grade': data.get('max_grade', 100),
            'term': data.get('term', 1),
            'academic_year': data.get('academic_year', datetime.utcnow().year),
            'exam_type': data.get('exam_type', 'end_of_term'),
            'comments': data.get('comments', ''),
            'entered_by': get_current_user()['_id'],
            'entered_by_name': get_current_user().get('name'),
            'entered_at': datetime.utcnow(),
            'class_id': student.get('class_id'),
            'class_name': student.get('class_name')
        }
        
        grades.insert_one(grade)
        
        # Log the action
        log_audit('create', 'grade', grade_id, {
            'student_id': data['student_id'],
            'student_name': student['name'],
            'subject': data['subject'],
            'grade': grade_value
        })
        
        logger.info(f"✅ Grade added: {student['name']} - {data['subject']}: {grade_value}")
        
        return jsonify({
            'success': True,
            'message': 'Grade added successfully',
            'grade': serialize_document(grade)
        }), 201
        
    except Exception as e:
        logger.error(f"Add grade error: {e}")
        logger.error(traceback.format_exc())
        return jsonify({'error': 'Failed to add grade'}), 500

@app.route('/api/grades', methods=['GET'])
@token_required
def get_grades():
    try:
        # Build query based on filters
        query = {}
        
        # Filter by student
        if 'student_id' in request.args:
            student_id = request.args['student_id'].strip()
            if student_id:
                query['student_id'] = student_id
        
        # Filter by class
        if 'class_id' in request.args:
            class_id = request.args['class_id'].strip()
            if class_id:
                query['class_id'] = class_id
        
        # Filter by subject
        if 'subject' in request.args:
            subject = request.args['subject'].strip()
            if subject:
                query['subject'] = subject
        
        # Filter by term
        if 'term' in request.args:
            try:
                query['term'] = int(request.args['term'])
            except ValueError:
                pass
        
        # Filter by academic year
        if 'academic_year' in request.args:
            try:
                query['academic_year'] = int(request.args['academic_year'])
            except ValueError:
                pass
        
        # Filter by exam type
        if 'exam_type' in request.args:
            exam_type = request.args['exam_type'].strip()
            if exam_type:
                query['exam_type'] = exam_type
        
        # Pagination
        page = max(1, int(request.args.get('page', 1)))
        per_page = min(100, max(1, int(request.args.get('per_page', 50))))
        skip = (page - 1) * per_page
        
        # Sorting
        sort_field = request.args.get('sort', 'entered_at')
        sort_direction = DESCENDING if request.args.get('order', 'desc') == 'desc' else ASCENDING
        sort_option = [(sort_field, sort_direction)]
        
        # Get grades
        grades_list = list(grades.find(query).sort(sort_option).skip(skip).limit(per_page))
        total = grades.count_documents(query)
        
        return jsonify({
            'success': True,
            'grades': [serialize_document(g) for g in grades_list],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total,
                'pages': (total + per_page - 1) // per_page
            }
        })
        
    except Exception as e:
        logger.error(f"Get grades error: {e}")
        logger.error(traceback.format_exc())
        return jsonify({'error': 'Failed to load grades'}), 500

@app.route('/api/grades/student/<student_id>', methods=['GET'])
@token_required
def get_student_grades_route(student_id):
    """Get all grades for a specific student (alternative endpoint)"""
    try:
        student = students.find_one({'_id': student_id})
        if not student:
            return jsonify({'error': 'Student not found'}), 404
        
        # Build query with filters
        query = {'student_id': student_id}
        
        if 'subject' in request.args:
            query['subject'] = request.args['subject']
        
        if 'term' in request.args:
            try:
                query['term'] = int(request.args['term'])
            except ValueError:
                pass
        
        if 'academic_year' in request.args:
            try:
                query['academic_year'] = int(request.args['academic_year'])
            except ValueError:
                pass
        
        student_grades = list(grades.find(query).sort([('academic_year', DESCENDING), ('term', DESCENDING)]))
        
        # Calculate statistics
        if student_grades:
            grades_list = [g['grade'] for g in student_grades]
            overall_stats = {
                'average': round(sum(grades_list) / len(grades_list), 2),
                'highest': max(grades_list),
                'lowest': min(grades_list),
                'total_grades': len(student_grades),
                'total_subjects': len(set(g['subject'] for g in student_grades))
            }
            
            # Group by subject
            subject_grades = {}
            for grade in student_grades:
                subject = grade['subject']
                if subject not in subject_grades:
                    subject_grades[subject] = []
                subject_grades[subject].append(grade['grade'])
            
            subject_stats = []
            for subject, grade_list in subject_grades.items():
                subject_stats.append({
                    'subject': subject,
                    'average': round(sum(grade_list) / len(grade_list), 2),
                    'highest': max(grade_list),
                    'lowest': min(grade_list),
                    'count': len(grade_list)
                })
        else:
            overall_stats = {
                'average': 0,
                'highest': 0,
                'lowest': 0,
                'total_grades': 0,
                'total_subjects': 0
            }
            subject_stats = []
        
        return jsonify({
            'success': True,
            'student': {
                '_id': student['_id'],
                'name': student['name'],
                'class_id': student.get('class_id'),
                'class_name': student.get('class_name')
            },
            'grades': [serialize_document(g) for g in student_grades],
            'overall_statistics': overall_stats,
            'subject_statistics': subject_stats
        })
        
    except Exception as e:
        logger.error(f"Get student grades error: {e}")
        return jsonify({'error': 'Failed to load student grades'}), 500

@app.route('/api/grades/class/<class_id>', methods=['GET'])
@token_required
def get_class_grades_route(class_id):
    """Get all grades for a specific class"""
    try:
        class_doc = classes.find_one({'_id': class_id})
        if not class_doc:
            return jsonify({'error': 'Class not found'}), 404
        
        # Get all students in class
        class_students = list(students.find({'class_id': class_id}))
        student_ids = [s['_id'] for s in class_students]
        
        if not student_ids:
            return jsonify({
                'success': True,
                'class': serialize_document(class_doc),
                'grades': [],
                'subject_statistics': [],
                'student_count': 0
            })
        
        # Build query
        query = {'student_id': {'$in': student_ids}}
        
        if 'subject' in request.args:
            query['subject'] = request.args['subject']
        
        if 'term' in request.args:
            try:
                query['term'] = int(request.args['term'])
            except ValueError:
                pass
        
        if 'academic_year' in request.args:
            try:
                query['academic_year'] = int(request.args['academic_year'])
            except ValueError:
                pass
        
        class_grades = list(grades.find(query))
        
        # Calculate class statistics
        if class_grades:
            grades_list = [g['grade'] for g in class_grades]
            class_stats = {
                'average': round(sum(grades_list) / len(grades_list), 2),
                'highest': max(grades_list),
                'lowest': min(grades_list),
                'total_grades': len(class_grades)
            }
            
            # Group by subject
            subject_grades = {}
            for grade in class_grades:
                subject = grade['subject']
                if subject not in subject_grades:
                    subject_grades[subject] = []
                subject_grades[subject].append(grade['grade'])
            
            subject_stats = []
            for subject, grade_list in subject_grades.items():
                # Get unique students for this subject
                subject_student_ids = set(g['student_id'] for g in class_grades if g['subject'] == subject)
                
                subject_stats.append({
                    'subject': subject,
                    'class_average': round(sum(grade_list) / len(grade_list), 2),
                    'student_count': len(subject_student_ids),
                    'grade_count': len(grade_list)
                })
        else:
            class_stats = {
                'average': 0,
                'highest': 0,
                'lowest': 0,
                'total_grades': 0
            }
            subject_stats = []
        
        return jsonify({
            'success': True,
            'class': serialize_document(class_doc),
            'grades': [serialize_document(g) for g in class_grades],
            'statistics': class_stats,
            'subject_statistics': subject_stats,
            'student_count': len(class_students)
        })
        
    except Exception as e:
        logger.error(f"Get class grades error: {e}")
        return jsonify({'error': 'Failed to load class grades'}), 500

@app.route('/api/grades/<grade_id>', methods=['GET'])
@token_required
def get_grade(grade_id):
    try:
        grade = grades.find_one({'_id': grade_id})
        if not grade:
            return jsonify({'error': 'Grade not found'}), 404
        
        return jsonify({
            'success': True,
            'grade': serialize_document(grade)
        })
        
    except Exception as e:
        logger.error(f"Get grade error: {e}")
        return jsonify({'error': 'Failed to load grade details'}), 500

@app.route('/api/grades/<grade_id>', methods=['PUT'])
@token_required
@role_required('admin', 'teacher')
def update_grade_route(grade_id):
    try:
        require_json()
        data = request.get_json()
        
        grade = grades.find_one({'_id': grade_id})
        if not grade:
            return jsonify({'error': 'Grade not found'}), 404
        
        # Track changes for audit
        changes = {}
        update_data = {}
        
        # Update fields
        updatable_fields = ['subject', 'grade', 'max_grade', 'term', 'academic_year', 'exam_type', 'comments']
        
        for field in updatable_fields:
            if field in data:
                old_value = grade.get(field)
                new_value = data[field]
                
                if old_value != new_value:
                    changes[field] = {'old': old_value, 'new': new_value}
                    update_data[field] = new_value
        
        # Validate grade value if being updated
        if 'grade' in update_data:
            try:
                grade_value = float(update_data['grade'])
                if not (0 <= grade_value <= 100):
                    return jsonify({'error': 'Grade must be between 0 and 100'}), 400
            except ValueError:
                return jsonify({'error': 'Grade must be a number'}), 400
        
        if not update_data:
            return jsonify({'error': 'No changes provided'}), 400
        
        update_data['updated_at'] = datetime.utcnow()
        
        # Perform update
        result = grades.update_one(
            {'_id': grade_id},
            {'$set': update_data}
        )
        
        if result.modified_count == 0:
            return jsonify({'error': 'No changes made'}), 400
        
        # Log changes
        if changes:
            log_audit('update', 'grade', grade_id, changes)
        
        logger.info(f"✅ Grade updated: {grade_id}")
        
        return jsonify({
            'success': True,
            'message': 'Grade updated successfully',
            'changes': changes
        })
        
    except Exception as e:
        logger.error(f"Update grade error: {e}")
        logger.error(traceback.format_exc())
        return jsonify({'error': 'Failed to update grade'}), 500

@app.route('/api/grades/<grade_id>', methods=['DELETE'])
@token_required
@role_required('admin')
def delete_grade_route(grade_id):
    try:
        grade = grades.find_one({'_id': grade_id})
        if not grade:
            return jsonify({'error': 'Grade not found'}), 404
        
        # Store grade data for audit
        grade_data = serialize_document(grade)
        
        # Delete grade
        result = grades.delete_one({'_id': grade_id})
        
        if result.deleted_count == 0:
            return jsonify({'error': 'Failed to delete grade'}), 500
        
        # Log the action
        log_audit('delete', 'grade', grade_id, {'grade_data': grade_data})
        
        logger.info(f"✅ Grade deleted: {grade_id} for student {grade['student_name']}")
        
        return jsonify({
            'success': True,
            'message': 'Grade deleted successfully'
        })
        
    except Exception as e:
        logger.error(f"Delete grade error: {e}")
        logger.error(traceback.format_exc())
        return jsonify({'error': 'Failed to delete grade'}), 500

# ------------------------
# Search Endpoints
# ------------------------
@app.route('/api/search', methods=['GET'])
@token_required
def search_all():
    try:
        query = request.args.get('q', '').strip()
        if not query or len(query) < 2:
            return jsonify({'error': 'Search query must be at least 2 characters'}), 400
        
        search_results = {
            'students': [],
            'staff': [],
            'classes': []
        }
        
        # Search students
        student_results = students.find({
            '$or': [
                {'name': {'$regex': query, '$options': 'i'}},
                {'_id': {'$regex': query, '$options': 'i'}},
                {'parent_contact': {'$regex': query, '$options': 'i'}},
                {'parent_email': {'$regex': query, '$options': 'i'}}
            ]
        }).limit(10)
        search_results['students'] = [serialize_document(s) for s in student_results]
        
        # Search staff
        staff_results = staff.find({
            '$or': [
                {'name': {'$regex': query, '$options': 'i'}},
                {'email': {'$regex': query, '$options': 'i'}},
                {'phone': {'$regex': query, '$options': 'i'}},
                {'department': {'$regex': query, '$options': 'i'}}
            ]
        }).limit(10)
        search_results['staff'] = [serialize_document(s) for s in staff_results]
        
        # Search classes
        class_results = classes.find({
            '$or': [
                {'name': {'$regex': query, '$options': 'i'}},
                {'level': {'$regex': query, '$options': 'i'}},
                {'stream': {'$regex': query, '$options': 'i'}},
                {'room_number': {'$regex': query, '$options': 'i'}}
            ]
        }).limit(10)
        search_results['classes'] = [serialize_document(c) for c in class_results]
        
        return jsonify({
            'success': True,
            'query': query,
            'results': search_results,
            'counts': {
                'students': len(search_results['students']),
                'staff': len(search_results['staff']),
                'classes': len(search_results['classes'])
            }
        })
        
    except Exception as e:
        logger.error(f"Search error: {e}")
        return jsonify({'error': 'Search failed'}), 500

# ------------------------
# Health Check and System Status
# ------------------------
@app.route('/api/health', methods=['GET'])
def health_check():
    try:
        # Test MongoDB connection
        client.server_info()
        db_status = 'connected'
        
        # Get collection counts
        counts = {
            'students': students.count_documents({}),
            'staff': staff.count_documents({}),
            'classes': classes.count_documents({}),
            'grades': grades.count_documents({}),
            'users': users.count_documents({})
        }
        
        # Get server info
        server_info = {
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'database': db_status,
            'version': '2.0.0',
            'country': 'Uganda',
            'system': 'School Management System',
            'environment': 'production' if not app.config['DEBUG'] else 'development',
            'uptime': str(datetime.utcnow() - app_start_time) if 'app_start_time' in globals() else 'unknown'
        }
        
        return jsonify({
            **server_info,
            'counts': counts
        })
        
    except Exception as e:
        logger.error(f"Health check error: {e}")
        return jsonify({
            'status': 'unhealthy',
            'timestamp': datetime.utcnow().isoformat(),
            'database': f'error: {str(e)}',
            'version': '2.0.0',
            'country': 'Uganda',
            'system': 'School Management System',
            'error': str(e)
        }), 500

@app.route('/api/system/info', methods=['GET'])
@token_required
@role_required('admin')
def system_info():
    """Get detailed system information"""
    try:
        # Get database stats
        db_stats = db.command('dbStats')
        
        # Get server status
        server_status = db.command('serverStatus')
        
        # Get collection stats
        collections = {}
        for collection_name in db.list_collection_names():
            stats = db.command('collStats', collection_name)
            collections[collection_name] = {
                'count': stats.get('count', 0),
                'size': stats.get('size', 0),
                'storageSize': stats.get('storageSize', 0),
                'totalIndexSize': stats.get('totalIndexSize', 0)
            }
        
        # Get recent audit logs count
        recent_audit_count = audit_logs.count_documents({
            'timestamp': {'$gte': datetime.utcnow() - timedelta(hours=24)}
        })
        
        # Get active users count (logged in last 24 hours)
        active_users_count = users.count_documents({
            'last_login': {'$gte': datetime.utcnow() - timedelta(hours=24)}
        })
        
        return jsonify({
            'success': True,
            'database': {
                'name': db_stats.get('db', 'unknown'),
                'collections': db_stats.get('collections', 0),
                'objects': db_stats.get('objects', 0),
                'dataSize': db_stats.get('dataSize', 0),
                'storageSize': db_stats.get('storageSize', 0),
                'indexes': db_stats.get('indexes', 0),
                'indexSize': db_stats.get('indexSize', 0)
            },
            'server': {
                'host': server_status.get('host', 'unknown'),
                'version': server_status.get('version', 'unknown'),
                'uptime': server_status.get('uptime', 0),
                'connections': server_status.get('connections', {})
            },
            'collections': collections,
            'activity': {
                'recent_audit_logs': recent_audit_count,
                'active_users': active_users_count
            },
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"System info error: {e}")
        return jsonify({'error': 'Failed to get system information'}), 500

# ------------------------
# Error Handlers
# ------------------------
@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'error': 'Resource not found',
        'path': request.path,
        'method': request.method,
        'timestamp': datetime.utcnow().isoformat()
    }), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f'Server error: {error}')
    logger.error(traceback.format_exc())
    return jsonify({
        'error': 'Internal server error',
        'message': 'An unexpected error occurred',
        'timestamp': datetime.utcnow().isoformat()
    }), 500

@app.errorhandler(400)
def bad_request(error):
    return jsonify({
        'error': 'Bad request',
        'message': str(error) if str(error) else 'Invalid request parameters',
        'timestamp': datetime.utcnow().isoformat()
    }), 400

@app.errorhandler(401)
def unauthorized(error):
    return jsonify({
        'error': 'Unauthorized',
        'message': 'Authentication required',
        'timestamp': datetime.utcnow().isoformat()
    }), 401

@app.errorhandler(403)
def forbidden(error):
    return jsonify({
        'error': 'Forbidden',
        'message': 'Insufficient permissions',
        'timestamp': datetime.utcnow().isoformat()
    }), 403

@app.errorhandler(415)
def unsupported_media_type(error):
    return jsonify({
        'error': 'Unsupported media type',
        'message': 'Content-Type must be application/json',
        'timestamp': datetime.utcnow().isoformat()
    }), 415

# ------------------------
# Initialize and Run
# ------------------------
if __name__ == '__main__':
    try:
        # Record app start time
        global app_start_time
        app_start_time = datetime.utcnow()
        
        # ------------------------
        # Safe Admin Initialization
        # ------------------------
        admin_email = "nexvoidcybertech@gmail.com"
        
        # First, check in users collection (since your login system uses users collection)
        if users.find_one({"email": admin_email}):
            logger.info("✅ Admin user already exists in users collection")
        else:
            admin_user = {
                '_id': str(uuid.uuid4()),
                'email': admin_email,
                'password': hash_password("Admin@2024!"),
                'role': 'admin',
                'name': 'System Administrator',
                'created_at': datetime.utcnow(),
                'updated_at': datetime.utcnow(),
                'is_active': True,
                'last_login': None,
                'profile_picture': None,
                'phone': '+256700000000',
                'department': 'Administration'
            }
            
            try:
                users.insert_one(admin_user)
                logger.info("✅ Admin user created successfully in users collection")
                logger.info(f"   Email: {admin_email}")
                logger.info(f"   Password: Admin@2024!")
            except Exception as e:
                logger.error(f"Failed to create admin user: {e}")
        
        # Also check in staff collection for consistency
        if staff.find_one({"email": admin_email}):
            logger.info("✅ Admin already exists in staff collection")
        else:
            staff_admin = {
                '_id': f"STAFF-{str(uuid.uuid4())[:8].upper()}",
                'name': 'System Administrator',
                'email': admin_email,
                'phone': '+256700000000',
                'role': 'admin',
                'department': 'Administration',
                'subjects': [],
                'classes_taught': [],
                'qualifications': [],
                'employment_date': datetime.utcnow().date().isoformat(),
                'bio': 'System Administrator',
                'profile_picture': None,
                'address': '',
                'district': 'Kampala',
                'status': 'active',
                'created_at': datetime.utcnow(),
                'updated_at': datetime.utcnow(),
                'created_by': 'system'
            }
            
            try:
                staff.insert_one(staff_admin)
                logger.info("✅ Admin staff record created successfully")
            except Exception as e:
                logger.error(f"Failed to create admin staff record: {e}")
        
        # ------------------------
        # Safe Index Creation for staff collection
        # ------------------------
        try:
            existing_indexes = staff.index_information()
            if "email_1" not in existing_indexes:
                staff.create_index([("email", ASCENDING)], unique=True)
                logger.info("✅ Staff email index created successfully")
            else:
                logger.info("📊 Staff email index already exists")
        except Exception as e:
            logger.error(f"Failed to create staff email index: {e}")
        
        # Also ensure other important indexes exist
        try:
            # Check and create user email index if needed
            user_indexes = users.index_information()
            if "email_1" not in user_indexes:
                users.create_index([("email", ASCENDING)], unique=True)
                logger.info("✅ Users email index created successfully")
        except Exception as e:
            logger.error(f"Failed to create user email index: {e}")
        
        logger.info("=" * 50)
        logger.info("🚀 Uganda School Management System Backend")
        logger.info("=" * 50)
        logger.info(f"📦 Version: 2.0.0")
        logger.info(f"🌍 Country: Uganda")
        logger.info(f"🔐 Environment: {'Development' if app.config['DEBUG'] else 'Production'}")
        logger.info(f"📊 Database: MongoDB Atlas")
        logger.info(f"🔑 JWT Expiry: {app.config['TOKEN_EXPIRY_HOURS']} hours")
        logger.info(f"🌐 CORS: Enabled for frontend origins")
        logger.info("=" * 50)
        logger.info("✅ Backend initialized successfully!")
        
        # ------------------------
        # Start Server
        # ------------------------
        port = int(os.getenv('PORT', 5000))
        
        if app.config['DEBUG']:
            # Development server with debug mode
            logger.info(f"🔧 Starting in DEBUG mode on port {port}...")
            app.run(
                host='0.0.0.0',
                port=port,
                debug=True,
                threaded=True,
                use_reloader=False  # Disable reloader to avoid double initialization
            )
        else:
            # Production server with Waitress
            from waitress import serve
            logger.info(f"🚀 Starting production server on port {port} with Waitress...")
            serve(
                app,
                host='0.0.0.0',
                port=port,
                threads=8,
                url_prefix='',  # Remove url_prefix as your routes already have /api prefix
                ident='Uganda-School-Management'
            )
            
    except KeyboardInterrupt:
        logger.info("👋 Server shutdown requested by user")
    except Exception as e:
        import traceback
        logger.error(f"❌ Failed to start server: {e}")
        logger.error(traceback.format_exc())
        raise