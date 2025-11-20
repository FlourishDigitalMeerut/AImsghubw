import secrets
import logging
import time
from datetime import datetime, timezone, timedelta
from bson import ObjectId
from fastapi import HTTPException
from services.database import get_users_collection, get_password_reset_sessions_collection
from services.email_sender import email_sender
from utils.security import get_password_hash
from collections import defaultdict

logger = logging.getLogger(__name__)

class OTPRateLimiter:
    def __init__(self):
        # Store: email -> {last_request_time, request_count, failed_attempts, locked_until}
        self.rate_limit_data = defaultdict(lambda: {
            'last_request_time': 0,
            'request_count': 0,
            'failed_attempts': 0,
            'locked_until': 0
        })
    
    def is_locked(self, email: str) -> bool:
        """Check if email is currently locked"""
        data = self.rate_limit_data[email]
        if data['locked_until'] > time.time():
            return True
        # Reset failed attempts if lock period expired
        if data['locked_until'] > 0 and data['locked_until'] <= time.time():
            data['failed_attempts'] = 0
            data['locked_until'] = 0
        return False
    
    def check_cooldown(self, email: str) -> bool:
        """Check if 1-minute cooldown has passed since last request"""
        data = self.rate_limit_data[email]
        current_time = time.time()
        return current_time - data['last_request_time'] >= 60
    
    def check_hourly_limit(self, email: str) -> bool:
        """Check if user has exceeded 3 requests per hour"""
        data = self.rate_limit_data[email]
        # Reset count if it's been more than 1 hour since first request
        if data['last_request_time'] > 0 and (time.time() - data['last_request_time']) >= 3600:
            data['request_count'] = 0
        return data['request_count'] < 3
    
    def record_request(self, email: str):
        """Record an OTP request"""
        data = self.rate_limit_data[email]
        data['last_request_time'] = time.time()
        data['request_count'] += 1
    
    def record_failed_attempt(self, email: str):
        """Record a failed OTP attempt and lock if needed"""
        data = self.rate_limit_data[email]
        data['failed_attempts'] += 1
        
        if data['failed_attempts'] >= 5:
            # Lock for 15 minutes
            data['locked_until'] = time.time() + 900  # 15 minutes in seconds
            return True
        return False
    
    def reset_failed_attempts(self, email: str):
        """Reset failed attempts on successful OTP verification"""
        data = self.rate_limit_data[email]
        data['failed_attempts'] = 0
        data['locked_until'] = 0

# Global instance
otp_rate_limiter = OTPRateLimiter()

class OTPService:
    
    @staticmethod
    def generate_otp(length=6):
        """Generate a numeric OTP"""
        return ''.join([str(secrets.randbelow(10)) for _ in range(length)])
    
    @staticmethod
    async def create_otp_for_user(email: str, session_token: str):
        """Create and store OTP for password reset with rate limiting"""
        try:
            # Check rate limits
            if otp_rate_limiter.is_locked(email):
                remaining_time = otp_rate_limiter.rate_limit_data[email]['locked_until'] - time.time()
                raise HTTPException(
                    status_code=429, 
                    detail=f"Too many failed attempts. Try again in {int(remaining_time/60)} minutes"
                )
            
            if not otp_rate_limiter.check_cooldown(email):
                raise HTTPException(
                    status_code=429, 
                    detail="Please wait 1 minute before requesting another OTP"
                )
            
            if not otp_rate_limiter.check_hourly_limit(email):
                raise HTTPException(
                    status_code=429, 
                    detail="Maximum 3 OTP requests per hour exceeded"
                )
            
            users_collection = await get_users_collection()
            
            # Check if user exists (but don't reveal it)
            user = await users_collection.find_one({"email": email})
            if not user:
                # Security: don't reveal if email exists, but still apply rate limiting
                otp_rate_limiter.record_request(email)
                return {"success": True, "message": "If the email exists, OTP has been sent"}
            
            # Generate OTP
            otp = OTPService.generate_otp()
            expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
            
            # Store OTP in database
            await users_collection.update_one(
                {"email": email},
                {"$set": {
                    "reset_otp": otp,
                    "reset_otp_expires": expires_at,
                    "otp_attempts": 0,
                    "otp_verified": False,
                    "session_token": session_token  # Link session token to user
                }}
            )
            
            # Record the request for rate limiting
            otp_rate_limiter.record_request(email)
            
            # Send OTP via email
            email_sent = await email_sender.send_otp_email(email, otp)
            
            if not email_sent:
                # Fallback: log OTP for development
                logger.info(f"OTP for {email}: {otp}")
                return {
                    "success": True,
                    "message": "OTP generated (check logs for development)",
                    "development_otp": otp  # Remove in production
                }
            
            return {
                "success": True,
                "message": "OTP sent to your email successfully"
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error creating OTP: {e}")
            raise HTTPException(status_code=500, detail="Error generating OTP")
        
    @staticmethod
    async def resend_otp(session_token: str):
        """Resend OTP using existing session token"""
        try:
            # Get email from session token
            sessions_collection = await get_password_reset_sessions_collection()
            users_collection = await get_users_collection()
            
            # Verify session token is valid and not expired
            session = await sessions_collection.find_one({
                "session_token": session_token,
                "used": False,
                "expires_at": {"$gt": datetime.now(timezone.utc)}
            })
            
            if not session:
                raise HTTPException(status_code=400, detail="Invalid or expired session token")
            
            email = session["email"]
            
            # Check rate limits for resend
            if otp_rate_limiter.is_locked(email):
                remaining_time = otp_rate_limiter.rate_limit_data[email]['locked_until'] - time.time()
                raise HTTPException(
                    status_code=429, 
                    detail=f"Too many failed attempts. Try again in {int(remaining_time/60)} minutes"
                )
            
            if not otp_rate_limiter.check_cooldown(email):
                raise HTTPException(
                    status_code=429, 
                    detail="Please wait 1 minute before requesting another OTP"
                )
            
            if not otp_rate_limiter.check_hourly_limit(email):
                raise HTTPException(
                    status_code=429, 
                    detail="Maximum 3 OTP requests per hour exceeded"
                )
            
            # Check if user exists
            user = await users_collection.find_one({"email": email})
            if not user:
                # Security: don't reveal if email exists, but still apply rate limiting
                otp_rate_limiter.record_request(email)
                return {"success": True, "message": "If the email exists, OTP has been sent"}
            
            # Generate new OTP
            otp = OTPService.generate_otp()
            expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
            
            # Update OTP in database
            await users_collection.update_one(
                {"email": email},
                {"$set": {
                    "reset_otp": otp,
                    "reset_otp_expires": expires_at,
                    "otp_attempts": 0,  # Reset attempts counter
                    "otp_verified": False  # Reset verification status
                }}
            )
            
            # Record the request for rate limiting
            otp_rate_limiter.record_request(email)
            
            # Send new OTP via email
            email_sent = await email_sender.send_otp_email(email, otp)
            
            if not email_sent:
                # Fallback: log OTP for development
                logger.info(f"Resent OTP for {email}: {otp}")
                return {
                    "success": True,
                    "message": "OTP regenerated (check logs for development)",
                    "development_otp": otp  # Remove in production
                }
            
            return {
                "success": True,
                "message": "New OTP sent to your email successfully"
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error resending OTP: {e}")
            raise HTTPException(status_code=500, detail="Error resending OTP")
        
    @staticmethod
    async def verify_otp(session_token: str, otp: str):
        """Verify OTP using session token"""
        try:
            # Get email from session token
            users_collection = await get_users_collection()
            sessions_collection = await get_password_reset_sessions_collection()
            
            # Verify session token is valid
            session = await sessions_collection.find_one({
                "session_token": session_token,
                "used": False,
                "expires_at": {"$gt": datetime.now(timezone.utc)}
            })
            
            if not session:
                raise HTTPException(status_code=400, detail="Invalid or expired session token")
            
            email = session["email"]
            
            # Check if locked due to too many failed attempts
            if otp_rate_limiter.is_locked(email):
                remaining_time = otp_rate_limiter.rate_limit_data[email]['locked_until'] - time.time()
                raise HTTPException(
                    status_code=429, 
                    detail=f"Too many failed attempts. Try again in {int(remaining_time/60)} minutes"
                )
            
            user = await users_collection.find_one({"email": email})
            if not user:
                raise HTTPException(status_code=404, detail="User not found")
            
            # Verify session token matches the one stored with user
            if user.get("session_token") != session_token:
                raise HTTPException(status_code=400, detail="Invalid session token")
            
            # Security checks
            stored_otp = user.get("reset_otp")
            expires_at = user.get("reset_otp_expires")
            attempts = user.get("otp_attempts", 0)
            
            if not stored_otp or not expires_at:
                raise HTTPException(status_code=400, detail="OTP not requested or expired")
            
            # Handle timezone comparison
            current_time = datetime.now(timezone.utc)
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            
            if current_time > expires_at:
                raise HTTPException(status_code=400, detail="OTP has expired")
            
            if stored_otp != otp:
                # Increment attempt counter in database
                await users_collection.update_one(
                    {"email": email},
                    {"$inc": {"otp_attempts": 1}}
                )
                
                # Record failed attempt in rate limiter
                is_now_locked = otp_rate_limiter.record_failed_attempt(email)
                
                if is_now_locked:
                    raise HTTPException(
                        status_code=429, 
                        detail="Too many failed OTP attempts. Account locked for 15 minutes."
                    )
                else:
                    remaining_attempts = 5 - otp_rate_limiter.rate_limit_data[email]['failed_attempts']
                    raise HTTPException(
                        status_code=400, 
                        detail=f"Invalid OTP. {remaining_attempts} attempts remaining"
                    )
            
            # Mark OTP as verified and update session
            await users_collection.update_one(
                {"email": email},
                {"$set": {
                    "otp_verified": True,
                    "otp_verified_at": datetime.now(timezone.utc)
                }}
            )
            
            # Update session to mark OTP as verified
            await sessions_collection.update_one(
                {"session_token": session_token},
                {"$set": {"otp_verified": True}}
            )
            
            # Reset failed attempts on successful verification
            otp_rate_limiter.reset_failed_attempts(email)
            
            return {"success": True, "message": "OTP verified successfully"}
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error verifying OTP: {e}")
            raise HTTPException(status_code=500, detail="Error verifying OTP") 
               
    @staticmethod
    async def reset_password(session_token: str, new_password: str):
        """Reset password using session token after OTP verification"""
        try:
            users_collection = await get_users_collection()
            sessions_collection = await get_password_reset_sessions_collection()
            
            # Verify session token and OTP verification
            session = await sessions_collection.find_one({
                "session_token": session_token,
                "used": False,
                "otp_verified": True,
                "expires_at": {"$gt": datetime.now(timezone.utc)}
            })
            
            if not session:
                raise HTTPException(status_code=400, detail="Invalid session or OTP not verified")
            
            email = session["email"]
            
            user = await users_collection.find_one({"email": email})
            if not user:
                raise HTTPException(status_code=404, detail="User not found")
            
            # Check if OTP was verified
            if not user.get("otp_verified"):
                raise HTTPException(status_code=400, detail="OTP not verified. Please verify OTP first.")
            
            # Check if OTP verification is still valid (within reasonable time)
            verified_time = user.get("otp_verified_at")
            if verified_time:
                current_time = datetime.now(timezone.utc)
                if verified_time.tzinfo is None:
                    verified_time = verified_time.replace(tzinfo=timezone.utc)
                
                # If OTP was verified more than 30 minutes ago, require re-verification
                time_diff = current_time - verified_time
                if time_diff > timedelta(minutes=30):
                    raise HTTPException(status_code=400, detail="OTP verification expired. Please verify OTP again.")
            
            # Validate password strength
            if len(new_password) < 6:
                raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
            
            # Hash new password and update
            hashed_password = get_password_hash(new_password)
            await users_collection.update_one(
                {"email": email},
                {"$set": {
                    "hashed_password": hashed_password
                }, "$unset": {
                    # Clear all OTP-related fields for security
                    "reset_otp": "",
                    "reset_otp_expires": "",
                    "otp_attempts": "",
                    "otp_verified": "",
                    "otp_verified_at": "",
                    "session_token": ""
                }}
            )
            
            # Mark session as used
            await sessions_collection.update_one(
                {"session_token": session_token},
                {"$set": {"used": True}}
            )
            
            return {"success": True, "message": "Password reset successfully"}
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error resetting password: {e}")
            raise HTTPException(status_code=500, detail="Error resetting password")