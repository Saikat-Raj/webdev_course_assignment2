from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
from flask_jwt_extended import (
    JWTManager,
    jwt_required,
    create_access_token,
    create_refresh_token,
    get_jwt_identity,
)
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
from datetime import datetime, timedelta
import os
from functools import wraps
import re
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Configuration from environment variables
app.config["MONGO_URI"] = os.getenv(
    "MONGO_URI"
)
app.config["JWT_SECRET_KEY"] = os.getenv(
    "JWT_SECRET_KEY"
)
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(
    hours=int(os.getenv("JWT_ACCESS_TOKEN_HOURS", "1"))
)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(
    days=int(os.getenv("JWT_REFRESH_TOKEN_DAYS", "30"))
)

# Flask environment configuration
app.config["DEBUG"] = os.getenv("FLASK_DEBUG", "False").lower() == "true"
app.config["ENV"] = os.getenv("FLASK_ENV")

# Initialize extensions
mongo = PyMongo(app)
jwt = JWTManager(app)
CORS(app)

# Custom JSON encoder for ObjectId
import json
from bson import ObjectId


class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        return json.JSONEncoder.default(self, o)


app.json_encoder = JSONEncoder


# Helper functions
def validate_email(email):
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(pattern, email) is not None


def validate_password(password):
    # At least 8 characters, one uppercase, one lowercase, one digit, one special char
    pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
    return re.match(pattern, password) is not None


def validate_object_id(id_string):
    try:
        ObjectId(id_string)
        return True
    except:
        return False


# Error handlers
@app.errorhandler(400)
def bad_request(error):
    return (
        jsonify(
            {"status": "error", "message": "Bad request", "error_code": "BAD_REQUEST"}
        ),
        400,
    )


@app.errorhandler(401)
def unauthorized(error):
    return (
        jsonify(
            {
                "status": "error",
                "message": "Unauthorized access",
                "error_code": "UNAUTHORIZED",
            }
        ),
        401,
    )


@app.errorhandler(404)
def not_found(error):
    return (
        jsonify(
            {
                "status": "error",
                "message": "Resource not found",
                "error_code": "NOT_FOUND",
            }
        ),
        404,
    )


@app.errorhandler(500)
def internal_error(error):
    return (
        jsonify(
            {
                "status": "error",
                "message": "Internal server error",
                "error_code": "INTERNAL_ERROR",
            }
        ),
        500,
    )


# Authentication Routes
@app.route("/api/auth/register", methods=["POST"])
def register():
    try:
        data = request.get_json()

        # Validate required fields
        required_fields = ["email", "password", "role", "first_name", "last_name"]
        for field in required_fields:
            if field not in data:
                return (
                    jsonify(
                        {
                            "status": "error",
                            "message": f"Missing required field: {field}",
                            "error_code": "MISSING_FIELD",
                        }
                    ),
                    400,
                )

        # Validate email format
        if not validate_email(data["email"]):
            return (
                jsonify(
                    {
                        "status": "error",
                        "message": "Invalid email format",
                        "error_code": "INVALID_EMAIL",
                    }
                ),
                400,
            )

        # Validate password strength
        if not validate_password(data["password"]):
            return (
                jsonify(
                    {
                        "status": "error",
                        "message": "Password must be at least 8 characters with uppercase, lowercase, digit, and special character",
                        "error_code": "WEAK_PASSWORD",
                    }
                ),
                400,
            )

        # Validate role
        if data["role"] not in ["patient", "doctor"]:
            return (
                jsonify(
                    {
                        "status": "error",
                        "message": "Invalid role. Must be patient or doctor",
                        "error_code": "INVALID_ROLE",
                    }
                ),
                400,
            )

        # Check if user already exists
        existing_user = mongo.db.users.find_one({"email": data["email"]})
        if existing_user:
            return (
                jsonify(
                    {
                        "status": "error",
                        "message": "Email already exists",
                        "error_code": "EMAIL_EXISTS",
                    }
                ),
                409,
            )

        # Create user
        user_doc = {
            "email": data["email"],
            "password_hash": generate_password_hash(data["password"]),
            "role": data["role"],
            "first_name": data["first_name"],
            "last_name": data["last_name"],
            "phone": data.get("phone", ""),
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
            "is_active": True,
        }

        result = mongo.db.users.insert_one(user_doc)
        user_id = result.inserted_id

        # Create role-specific document
        if data["role"] == "doctor":
            doctor_doc = {
                "user_id": user_id,
                "license_number": data.get("license_number", ""),
                "specialty": data.get("specialty", ""),
                "rating": 0.0,
                "location": data.get("location", ""),
                "bio": data.get("bio", ""),
                "verified": False,
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow(),
            }
            mongo.db.doctors.insert_one(doctor_doc)

        elif data["role"] == "patient":
            # Parse date_of_birth if provided
            date_of_birth = None
            if data.get("date_of_birth"):
                try:
                    date_of_birth = datetime.strptime(data["date_of_birth"], "%Y-%m-%d")
                except ValueError:
                    return (
                        jsonify(
                            {
                                "status": "error",
                                "message": "Invalid date format. Use YYYY-MM-DD",
                                "error_code": "INVALID_DATE_FORMAT",
                            }
                        ),
                        400,
                    )

            patient_doc = {
                "user_id": user_id,
                "date_of_birth": date_of_birth,
                "gender": data.get("gender", ""),
                "medical_history": data.get("medical_history", []),
                "allergies": data.get("allergies", []),
                "current_medications": data.get("current_medications", []),
                "emergency_contact": data.get("emergency_contact", {}),
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow(),
            }
            mongo.db.patients.insert_one(patient_doc)

        return (
            jsonify(
                {
                    "status": "success",
                    "message": "Registration successful",
                    "data": {
                        "user_id": str(user_id),
                        "email": data["email"],
                        "role": data["role"],
                        "verification_required": True,
                    },
                }
            ),
            201,
        )

    except Exception as e:
        return (
            jsonify(
                {
                    "status": "error",
                    "message": "Registration failed",
                    "error_code": "REGISTRATION_FAILED",
                }
            ),
            500,
        )


@app.route("/api/auth/login", methods=["POST"])
def login():
    try:
        data = request.get_json()

        # Validate required fields
        if not data.get("email") or not data.get("password"):
            return (
                jsonify(
                    {
                        "status": "error",
                        "message": "Email and password are required",
                        "error_code": "MISSING_CREDENTIALS",
                    }
                ),
                400,
            )

        # Find user
        user = mongo.db.users.find_one({"email": data["email"]})
        if not user or not check_password_hash(user["password_hash"], data["password"]):
            return (
                jsonify(
                    {
                        "status": "error",
                        "message": "Invalid email or password",
                        "error_code": "INVALID_CREDENTIALS",
                    }
                ),
                401,
            )

        if not user["is_active"]:
            return (
                jsonify(
                    {
                        "status": "error",
                        "message": "Account is deactivated",
                        "error_code": "ACCOUNT_DEACTIVATED",
                    }
                ),
                401,
            )

        # Create tokens
        access_token = create_access_token(identity=str(user["_id"]))
        refresh_token = create_refresh_token(identity=str(user["_id"]))

        # Get user profile
        profile = {
            "first_name": user["first_name"],
            "last_name": user["last_name"],
            "phone": user.get("phone", ""),
        }

        return (
            jsonify(
                {
                    "status": "success",
                    "data": {
                        "access_token": access_token,
                        "refresh_token": refresh_token,
                        "user": {
                            "user_id": str(user["_id"]),
                            "email": user["email"],
                            "role": user["role"],
                            "profile": profile,
                        },
                        "expires_in": 3600,
                    },
                }
            ),
            200,
        )

    except Exception as e:
        return (
            jsonify(
                {
                    "status": "error",
                    "message": "Login failed",
                    "error_code": "LOGIN_FAILED",
                }
            ),
            500,
        )


# Role-based access control decorator
def role_required(allowed_roles):
    def decorator(f):
        @wraps(f)
        @jwt_required()
        def decorated_function(*args, **kwargs):
            user_id = get_jwt_identity()
            user = mongo.db.users.find_one({"_id": ObjectId(user_id)})

            if not user or user["role"] not in allowed_roles:
                return (
                    jsonify(
                        {
                            "status": "error",
                            "message": "Insufficient permissions",
                            "error_code": "INSUFFICIENT_PERMISSIONS",
                        }
                    ),
                    403,
                )

            return f(*args, **kwargs)

        return decorated_function

    return decorator


# Appointment Routes
@app.route("/api/appointments/doctors/available", methods=["GET"])
@jwt_required()
def get_available_doctors():
    try:
        # Get query parameters
        specialty = request.args.get("specialty")
        date_str = request.args.get("date")
        location = request.args.get("location")

        # Build query
        query = {}
        if specialty:
            query["specialty"] = {"$regex": specialty, "$options": "i"}
        if location:
            query["location"] = {"$regex": location, "$options": "i"}

        # Find doctors
        doctors = list(mongo.db.doctors.find(query))

        available_doctors = []
        for doctor in doctors:
            # Get user info
            user = mongo.db.users.find_one({"_id": doctor["user_id"]})
            if not user or not user["is_active"]:
                continue

            # Get available slots for the requested date
            available_slots = []
            if date_str:
                try:
                    requested_date = datetime.strptime(date_str, "%Y-%m-%d").date()

                    # Get doctor's schedule for the day
                    day_name = requested_date.strftime("%A").lower()
                    schedule = mongo.db.doctor_schedule.find_one(
                        {
                            "doctor_id": doctor["_id"],
                            "day_of_week": day_name,
                            "is_active": True,
                        }
                    )

                    if schedule:
                        # Generate time slots
                        start_time = datetime.strptime(
                            schedule["start_time"], "%H:%M"
                        ).time()
                        end_time = datetime.strptime(
                            schedule["end_time"], "%H:%M"
                        ).time()
                        appointment_duration = schedule.get("appointment_duration", 30)

                        # Check existing appointments for that date
                        existing_appointments = list(
                            mongo.db.appointments.find(
                                {
                                    "doctor_id": doctor["_id"],
                                    "appointment_date": requested_date,
                                    "status": {"$in": ["scheduled", "confirmed"]},
                                }
                            )
                        )

                        booked_times = [
                            apt["appointment_time"] for apt in existing_appointments
                        ]

                        # Generate available slots (simplified logic)
                        current_time = datetime.combine(requested_date, start_time)
                        end_datetime = datetime.combine(requested_date, end_time)

                        while current_time < end_datetime:
                            time_str = current_time.strftime("%H:%M")
                            if time_str not in booked_times:
                                available_slots.append(
                                    {
                                        "date": date_str,
                                        "time": time_str,
                                        "duration": appointment_duration,
                                    }
                                )
                            current_time += timedelta(minutes=appointment_duration)

                except ValueError:
                    return (
                        jsonify(
                            {
                                "status": "error",
                                "message": "Invalid date format. Use YYYY-MM-DD",
                                "error_code": "INVALID_DATE_FORMAT",
                            }
                        ),
                        400,
                    )

            doctor_info = {
                "doctor_id": str(doctor["_id"]),
                "name": f"Dr. {user['first_name']} {user['last_name']}",
                "specialty": doctor.get("specialty", ""),
                "rating": doctor.get("rating", 0.0),
                "available_slots": available_slots,
                "location": doctor.get("location", ""),
            }
            available_doctors.append(doctor_info)

        return jsonify({"status": "success", "data": available_doctors}), 200

    except Exception as e:
        return (
            jsonify(
                {
                    "status": "error",
                    "message": "Failed to retrieve available doctors",
                    "error_code": "RETRIEVAL_FAILED",
                }
            ),
            500,
        )


@app.route("/api/appointments/book", methods=["POST"])
@role_required(["patient"])
def book_appointment():
    try:
        data = request.get_json()
        user_id = get_jwt_identity()

        # Validate required fields
        required_fields = [
            "doctor_id",
            "appointment_date",
            "appointment_time",
            "reason",
        ]
        for field in required_fields:
            if field not in data:
                return (
                    jsonify(
                        {
                            "status": "error",
                            "message": f"Missing required field: {field}",
                            "error_code": "MISSING_FIELD",
                        }
                    ),
                    400,
                )

        # Validate object IDs
        if not validate_object_id(data["doctor_id"]):
            return (
                jsonify(
                    {
                        "status": "error",
                        "message": "Invalid doctor ID",
                        "error_code": "INVALID_DOCTOR_ID",
                    }
                ),
                400,
            )

        # Get patient info
        user = mongo.db.users.find_one({"_id": ObjectId(user_id)})
        patient = mongo.db.patients.find_one({"user_id": ObjectId(user_id)})

        if not patient:
            return (
                jsonify(
                    {
                        "status": "error",
                        "message": "Patient profile not found",
                        "error_code": "PATIENT_NOT_FOUND",
                    }
                ),
                404,
            )

        # Validate doctor exists
        doctor = mongo.db.doctors.find_one({"_id": ObjectId(data["doctor_id"])})
        if not doctor:
            return (
                jsonify(
                    {
                        "status": "error",
                        "message": "Doctor not found",
                        "error_code": "DOCTOR_NOT_FOUND",
                    }
                ),
                404,
            )

        # Validate date format
        try:
            appointment_date = datetime.strptime(
                data["appointment_date"], "%Y-%m-%d"
            ).date()
        except ValueError:
            return (
                jsonify(
                    {
                        "status": "error",
                        "message": "Invalid date format. Use YYYY-MM-DD",
                        "error_code": "INVALID_DATE_FORMAT",
                    }
                ),
                400,
            )

        # Validate time format
        try:
            datetime.strptime(data["appointment_time"], "%H:%M")
        except ValueError:
            return (
                jsonify(
                    {
                        "status": "error",
                        "message": "Invalid time format. Use HH:MM",
                        "error_code": "INVALID_TIME_FORMAT",
                    }
                ),
                400,
            )

        # Check for existing appointment at the same time
        existing_appointment = mongo.db.appointments.find_one(
            {
                "doctor_id": ObjectId(data["doctor_id"]),
                "appointment_date": appointment_date,
                "appointment_time": data["appointment_time"],
                "status": {"$in": ["scheduled", "confirmed"]},
            }
        )

        if existing_appointment:
            return (
                jsonify(
                    {
                        "status": "error",
                        "message": "Time slot already booked",
                        "error_code": "BOOKING_001",
                        "details": {
                            "requested_time": f"{data['appointment_date']}T{data['appointment_time']}:00",
                            "doctor_id": data["doctor_id"],
                        },
                    }
                ),
                409,
            )

        # Generate confirmation number
        confirmation_number = f"MC-{appointment_date.strftime('%Y-%m%d')}-{mongo.db.appointments.count_documents({}) + 1:03d}"

        # Create appointment
        appointment_doc = {
            "patient_id": patient["_id"],
            "doctor_id": ObjectId(data["doctor_id"]),
            "appointment_date": appointment_date,
            "appointment_time": data["appointment_time"],
            "duration": data.get("duration", 30),
            "status": "confirmed",
            "reason": data["reason"],
            "notes": data.get("notes", ""),
            "confirmation_number": confirmation_number,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
        }

        result = mongo.db.appointments.insert_one(appointment_doc)
        appointment_id = result.inserted_id

        return (
            jsonify(
                {
                    "status": "success",
                    "data": {
                        "appointment_id": str(appointment_id),
                        "confirmation_number": confirmation_number,
                        "video_room_url": f"https://mediconnect.com/video/{appointment_id}",
                        "calendar_file_url": f"https://mediconnect.com/calendar/{appointment_id}.ics",
                    },
                }
            ),
            201,
        )

    except Exception as e:
        return (
            jsonify(
                {
                    "status": "error",
                    "message": "Failed to book appointment",
                    "error_code": "BOOKING_FAILED",
                }
            ),
            500,
        )


@app.route("/api/health", methods=["GET"])
def health_check():
    """Health check endpoint"""
    return (
        jsonify(
            {
                "status": "success",
                "message": "MediConnect API is running",
                "timestamp": datetime.utcnow().isoformat(),
                "environment": os.getenv("FLASK_ENV"),
            }
        ),
        200,
    )


if __name__ == "__main__":
    # Get host and port from environment variables
    host = os.getenv("FLASK_HOST", "0.0.0.0")
    port = int(os.getenv("FLASK_PORT", "5000"))
    debug = os.getenv("FLASK_DEBUG", "True").lower() == "true"
    
    app.run(debug=debug, host=host, port=port)
