import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
from datetime import datetime

logger = logging.getLogger(__name__)

class EmailSender:
    def __init__(self):
        self.smtp_server = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
        self.smtp_port = int(os.getenv('SMTP_PORT', 587))
        self.smtp_username = os.getenv('SMTP_USERNAME')
        self.smtp_password = os.getenv('SMTP_PASSWORD')
        self.from_email = os.getenv('FROM_EMAIL', self.smtp_username)

    async def send_otp_email(self, to_email: str, otp: str) -> bool:
        """Send OTP email using SMTP"""
        try:
            # Create message
            subject = "Your AiMsgHub Verification Code For Password Reset"
            body = self._create_otp_email_body(otp)
            
            msg = MIMEMultipart()
            msg['From'] = self.from_email
            msg['To'] = to_email
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'html'))

            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()  # Enable security
                server.login(self.smtp_username, self.smtp_password)
                server.send_message(msg)

            logger.info(f"OTP email sent to {to_email}")
            return True

        except Exception as e:
            logger.error(f"Failed to send OTP email: {str(e)}")
            return False

    def _create_otp_email_body(self, otp: str) -> str:
        """Create HTML email body for OTP"""
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: #4f46e5; color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }}
                .content {{ background: #f9fafb; padding: 30px; border-radius: 0 0 10px 10px; }}
                .otp-code {{ font-size: 32px; font-weight: bold; text-align: center; color: #4f46e5; margin: 20px 0; }}
                .footer {{ text-align: center; margin-top: 20px; font-size: 12px; color: #666; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>AiMsgHub</h1>
                    <p>Password Reset Verification</p>
                </div>
                <div class="content">
                    <h2>Your Verification Code</h2>
                    <p>Use the following code to reset your password:</p>
                    <div class="otp-code">{otp}</div>
                    <p>This code will expire in 10 minutes.</p>
                    <p>If you didn't request this password reset, please ignore this email.</p>
                </div>
                <div class="footer">
                    <p>&copy; 2025 AiMsgHub. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        """

# Global instance
email_sender = EmailSender()