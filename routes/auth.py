from fastapi import APIRouter, HTTPException, status, Header, Depends
from models.users import UserCreate, UserResponse, UserLogin
from models.tokens import Token, TokenRefresh  
from services.database import get_users_collection
from services.auth import get_current_user, authenticate_user
from services.token_service import TokenService  
from utils.security import get_password_hash
from datetime import datetime, timezone, timedelta
from models.users import UserProfileResponse
from models.users import ForgotPasswordRequest, VerifyOTPRequest, ResetPasswordRequest
from services.otp_service import OTPService
import logging

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["authentication"])

@router.post("/signup", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def signup(user: UserCreate):
    users_collection = await get_users_collection()
    
    existing_user = await users_collection.find_one({
        "$or": [
            {"email": user.email},
            {"username": user.username}
        ]
    })
    if existing_user:
        raise HTTPException(status_code=400, detail="Email or username already registered")
    
    new_user = {
        "email": user.email,
        "username": user.username,
        "mobile_number": user.mobile_number,
        "hashed_password": get_password_hash(user.password),
        "whatsapp_account_verified": False,
        "chatbot_active": True,
        "created_at": datetime.now(timezone.utc)
    }
    
    result = await users_collection.insert_one(new_user)
    
    logger.info(f"New user created: {user.email} ({user.username})")
    
    return UserResponse(
        id=str(result.inserted_id),
        username=user.username,
        mobile_number=user.mobile_number,
        email=user.email,
        whatsapp_account_verified=False,
        chatbot_active=True,
        created_at=new_user["created_at"].isoformat()
    )

@router.post("/login", response_model=Token)
async def login(user_credentials: UserLogin):
    user = await authenticate_user(user_credentials.email, user_credentials.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    
    # Use TokenService to create both tokens
    tokens = await TokenService.create_tokens_for_user(user)
    
    # Generate all API keys for the user
    from services.api_key_service import APIKeyService
    from services.database import get_api_keys_collection
    
    api_keys_collection = await get_api_keys_collection()
    generated_keys = await APIKeyService.generate_all_keys_for_user(str(user["_id"]), api_keys_collection)
    
    return {
        "message": "Login successful, Welcome!",
        "access_token": tokens["access_token"],
        "refresh_token": tokens["refresh_token"], 
        "token_type": tokens["token_type"],
        "user_id": str(user["_id"]),
        "email": user["email"],
        "expires_in": tokens["expires_in"],
        "api_keys": generated_keys  # Add API keys to response
    }

@router.post("/refresh", response_model=dict)
async def refresh_token(token_data: TokenRefresh):
    """Refresh access token using refresh token"""
    tokens = await TokenService.refresh_access_token(token_data.refresh_token)
    
    return {
        "message": "Token refreshed successfully",
        "access_token": tokens["access_token"],
        "token_type": tokens["token_type"],
        "expires_in": tokens["expires_in"]
    }

@router.post("/logout")
async def logout(refresh_token: str = None, current_user: dict = Depends(get_current_user)):
    """Logout user and revoke tokens"""
    if refresh_token:
        await TokenService.revoke_refresh_token(refresh_token)
    else:
        # Revoke all user tokens
        await TokenService.revoke_all_user_tokens(str(current_user["_id"]))
    
    return {"message": "Successfully logged out"}

@router.get("/user-profile", response_model=UserProfileResponse)
async def get_user_profile(current_user: dict = Depends(get_current_user)):
    
    try:
        basic_info = {
            "user_id": str(current_user["_id"]),
            "email": current_user.get("email", ""),
            "username": current_user.get("username", ""),
            "mobile_number": current_user.get("mobile_number", ""),
            "whatsapp_account_verified": current_user.get("whatsapp_account_verified", False),
            "chatbot_active": current_user.get("chatbot_active", True),
            "created_at": current_user.get("created_at", datetime.now(timezone.utc)).isoformat()
        }

        profile_response = {
            **basic_info,
            "whatsapp_marketing": await get_whatsapp_marketing_info(current_user),
            "email_marketing": await get_email_marketing_info(current_user),
            "sms_marketing": await get_sms_marketing_info(current_user),
            "devices": await get_devices_info(current_user),
            "business_profile": await get_business_profile_info(current_user),
            "api_keys_info": await get_api_keys_info(current_user),
            "campaign_stats": await get_campaign_stats(current_user)
        }
        
        return profile_response
        
    except Exception as e:
        logger.error(f"Error getting user profile: {e}")
        raise HTTPException(
            status_code=500, 
            detail=f"Error retrieving user profile: {str(e)}"
        )

async def get_whatsapp_marketing_info(current_user: dict):
    try:
        from services.database import get_whatsapp_campaigns_collection, get_whatsapp_contacts_collection
        
        campaigns_collection = await get_whatsapp_campaigns_collection()
        contacts_collection = await get_whatsapp_contacts_collection()
        
        total_campaigns = await campaigns_collection.count_documents({
            "user_id": current_user["_id"]
        })
        
        total_contacts = await contacts_collection.count_documents({
            "user_id": current_user["_id"]
        })

        active_campaigns = await campaigns_collection.count_documents({
            "user_id": current_user["_id"],
            "status": "Active"
        })
        
        return {
            "connected": current_user.get("whatsapp_account_verified", False),
            "phone_number_id": current_user.get("phone_number_id"),
            "total_campaigns": total_campaigns,
            "active_campaigns": active_campaigns,
            "total_contacts": total_contacts,
            "meta_api_configured": bool(current_user.get("meta_api_key"))
        }
    except Exception as e:
        logger.error(f"Error getting WhatsApp marketing info: {e}")
        return None

async def get_email_marketing_info(current_user: dict):
    try:
        from services.database import get_email_users_collection, get_email_logs_collection
        
        email_users_collection = await get_email_users_collection()
        email_user = await email_users_collection.find_one({
            "user_id": str(current_user["_id"])
        })
        
        if not email_user:
            return {"configured": False}
        
        email_logs_collection = await get_email_logs_collection()
        total_emails = await email_logs_collection.count_documents({
            "user_id": str(current_user["_id"])
        })
        
        return {
            "configured": True,
            "username": email_user.get("username"),
            "email": email_user.get("email"),
            "domain": email_user.get("domain"),
            "domain_verified": email_user.get("domain_verified", False),
            "total_emails_sent": total_emails,
            "subuser_id": email_user.get("subuser_id")
        }
    except Exception as e:
        logger.error(f"Error getting email marketing info: {e}")
        return None

async def get_sms_marketing_info(current_user: dict):
    try:
        from services.database import get_sms_users_collection, get_sms_logs_collection
        
        sms_users_collection = await get_sms_users_collection()
        sms_user = await sms_users_collection.find_one({
            "user_id": str(current_user["_id"])
        })
        
        if not sms_user:
            return {"configured": False}
        
        sms_logs_collection = await get_sms_logs_collection()
        total_sms = await sms_logs_collection.count_documents({
            "user_id": str(current_user["_id"])
        })
        
        return {
            "configured": True,
            "purchased_number": sms_user.get("purchased_number"),
            "number_verified": sms_user.get("number_verified", False),
            "sms_credits": sms_user.get("sms_credits", 0),
            "status": sms_user.get("status", "inactive"),
            "total_sms_sent": total_sms,
            "business_verified": sms_user.get("business_verified", False)
        }
    except Exception as e:
        logger.error(f"Error getting SMS marketing info: {e}")
        return None

async def get_devices_info(current_user: dict):
    try:
        from services.database import get_devices_collection
        
        devices_collection = await get_devices_collection()
        devices_cursor = devices_collection.find({
            "user_id": current_user["_id"]
        })
        devices = await devices_cursor.to_list(length=100)
        
        formatted_devices = []
        for device in devices:
            formatted_devices.append({
                "device_id": str(device["_id"]),
                "name": device.get("name", ""),
                "instance_id": device.get("instance_id", ""),
                "login_type": device.get("login_type", ""),
                "status": device.get("status", "inactive"),
                "phone_number": device.get("phone_number"),
                "created_at": device.get("created_at", datetime.now(timezone.utc)).isoformat()
            })
        
        return formatted_devices
    except Exception as e:
        logger.error(f"Error getting devices info: {e}")
        return None

async def get_business_profile_info(current_user: dict):
    try:
        from services.database import get_business_profiles_collection
        
        business_collection = await get_business_profiles_collection()
        business_profile = await business_collection.find_one({
            "user_id": str(current_user["_id"])
        })
        
        if not business_profile:
            return {"verified": False}
        
        return {
            "verified": business_profile.get("business_verified", False),
            "business_name": business_profile.get("business_name"),
            "business_type": business_profile.get("business_type"),
            "website": business_profile.get("website"),
            "business_email": business_profile.get("business_email"),
            "verified_at": business_profile.get("verified_at")
        }
    except Exception as e:
        logger.error(f"Error getting business profile info: {e}")
        return None

async def get_api_keys_info(current_user: dict):
    try:
        from services.database import get_api_keys_collection
        
        api_keys_collection = await get_api_keys_collection()
        user_keys = await api_keys_collection.find_one({
            "user_id": current_user["_id"]
        })
        
        if not user_keys:
            return {"keys_generated": False}
        
        keys_info = {}
        for scope, key_data in user_keys.get("keys", {}).items():
            keys_info[scope] = {
                "generated_at": key_data.get("generated_at"),
                "expires_at": key_data.get("expires_at"),
                "exists": True
            }
        
        return {
            "keys_generated": True,
            "scopes": list(keys_info.keys()),
            "key_details": keys_info,
            "last_rotated": user_keys.get("last_rotated")
        }
    except Exception as e:
        logger.error(f"Error getting API keys info: {e}")
        return None

async def get_campaign_stats(current_user: dict):
    """Get campaign statistics across all services"""
    try:
        from services.database import (
            get_whatsapp_campaigns_collection, 
            get_campaigns_collection,
            get_email_logs_collection,
            get_sms_logs_collection
        )
        
        whatsapp_campaigns_collection = await get_whatsapp_campaigns_collection()
        campaigns_collection = await get_campaigns_collection()
        email_logs_collection = await get_email_logs_collection()
        sms_logs_collection = await get_sms_logs_collection()
        
        whatsapp_stats = await whatsapp_campaigns_collection.aggregate([
            {"$match": {"user_id": current_user["_id"]}},
            {"$group": {
                "_id": None,
                "total_campaigns": {"$sum": 1},
                "total_messages": {"$sum": {"$add": ["$sent_count", "$failed_count"]}},
                "sent_messages": {"$sum": "$sent_count"},
                "failed_messages": {"$sum": "$failed_count"}
            }}
        ]).to_list(length=1)
        
        total_emails = await email_logs_collection.count_documents({
            "user_id": str(current_user["_id"])
        })
        
        total_sms = await sms_logs_collection.count_documents({
            "user_id": str(current_user["_id"])
        })
        
        whatsapp_data = whatsapp_stats[0] if whatsapp_stats else {}
        
        return {
            "whatsapp": {
                "total_campaigns": whatsapp_data.get("total_campaigns", 0),
                "total_messages": whatsapp_data.get("total_messages", 0),
                "sent_messages": whatsapp_data.get("sent_messages", 0),
                "failed_messages": whatsapp_data.get("failed_messages", 0)
            },
            "email": {
                "total_emails_sent": total_emails
            },
            "sms": {
                "total_sms_sent": total_sms
            },
            "total_campaigns": whatsapp_data.get("total_campaigns", 0)
        }
    except Exception as e:
        logger.error(f"Error getting campaign stats: {e}")
        return None

@router.post("/forgot-password")
async def forgot_password(request: ForgotPasswordRequest):
    """Step 1: Verify email exists + Send OTP"""
    try:
        import uuid
        session_token = str(uuid.uuid4())  # Keep the UUID, don't overwrite!
        
        # Store session token with email in database
        from services.database import get_password_reset_sessions_collection
        sessions_collection = await get_password_reset_sessions_collection()
        
        await sessions_collection.insert_one({
            "session_token": session_token,
            "email": request.email,
            "created_at": datetime.now(timezone.utc),
            "expires_at": datetime.now(timezone.utc) + timedelta(minutes=15),  
            "used": False,
            "otp_verified": False
        })
        
        result = await OTPService.create_otp_for_user(request.email, session_token)
        
        return {
            "success": True, 
            "message": "OTP sent to your email successfully",
            "session_token": session_token  # Return the UUID
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in forgot password: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/resend-otp")
async def resend_otp(
    x_session_token: str = Header(..., alias="X-Session-Token")
):
    """Resend OTP using existing session token"""
    try:
        result = await OTPService.resend_otp(x_session_token)
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error resending OTP: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
       
@router.post("/verify-otp")
async def verify_otp(
    request: VerifyOTPRequest,
    x_session_token: str = Header(..., alias="X-Session-Token")
):
    """Step 2: Verify OTP using session token"""
    try:
        result = await OTPService.verify_otp(x_session_token, request.otp)
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error verifying OTP: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/reset-password")
async def reset_password(
    request: ResetPasswordRequest,
    x_session_token: str = Header(..., alias="X-Session-Token")
):
    """Step 3: Reset password using session token"""
    try:
        if len(request.new_password) < 6:
            raise HTTPException(status_code=400, detail="Password must be at least 6 characters long")
        
        result = await OTPService.reset_password(x_session_token, request.new_password)
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error resetting password: {e}")
        raise HTTPException(status_code=500, detail="Error resetting password")