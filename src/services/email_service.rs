use lettre::{
    message::{header::ContentType, Mailbox},
    transport::smtp::authentication::Credentials,
    Message, SmtpTransport, Transport,
};
use std::env;

pub struct EmailService {
    mailer: SmtpTransport,
    from_email: Mailbox,
}

impl EmailService {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let smtp_host = env::var("SMTP_HOST").expect("SMTP_HOST must be set");
        let smtp_port: u16 = env::var("SMTP_PORT")
            .expect("SMTP_PORT must be set")
            .parse()
            .expect("SMTP_PORT must be a valid number");
        let smtp_username = env::var("SMTP_USERNAME").expect("SMTP_USERNAME must be set");
        let smtp_password = env::var("SMTP_PASSWORD").expect("SMTP_PASSWORD must be set");

        let from_email_str = env::var("SMTP_FROM_EMAIL").expect("SMTP_FROM_EMAIL must be set");
        let from_name = env::var("SMTP_FROM_NAME").expect("SMTP_FROM_NAME must be set");

        let credentials = Credentials::new(smtp_username, smtp_password);

        let mailer = SmtpTransport::starttls_relay(&smtp_host)?
            .port(smtp_port)
            .credentials(credentials)
            .build();

        let from_email = format!("{} <{}>", from_name, from_email_str)
            .parse()
            .expect("Invalid from email format");

        Ok(Self { mailer, from_email })
    }

    pub async fn send_verification_email(
        &self,
        to_email: &str,
        username: &str,
        verification_token: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let base_url = env::var("BASE_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());
        let verification_link = format!(
            "{}/api/auth/verify-email?token={}",
            base_url, verification_token
        );

        let html_body = format!(
            r#"
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                    .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                    .header {{ background-color: #4CAF50; color: white; padding: 20px; text-align: center; }}
                    .content {{ background-color: #f9f9f9; padding: 30px; border-radius: 5px; margin-top: 20px; }}
                    .button {{
                        display: inline-block;
                        padding: 12px 30px;
                        background-color: #4CAF50;
                        color: white;
                        text-decoration: none;
                        border-radius: 5px;
                        margin: 20px 0;
                    }}
                    .footer {{ text-align: center; margin-top: 20px; color: #666; font-size: 12px; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>Welcome to AxumAPI!</h1>
                    </div>
                    <div class="content">
                        <h2>Hi {}!</h2>
                        <p>Thanks for signing up! We're excited to have you on board.</p>
                        <p>Please verify your email address by clicking the button below:</p>
                        <div style="text-align: center;">
                            <a href="{}" class="button">Verify Email Address</a>
                        </div>
                        <p>Or copy and paste this link into your browser:</p>
                        <p style="background-color: #eee; padding: 10px; word-break: break-all;">{}</p>
                        <p><strong>This link will expire in 24 hours.</strong></p>
                        <p>If you didn't create an account, please ignore this email.</p>
                    </div>
                    <div class="footer">
                        <p>© 2024 AxumAPI. All rights reserved.</p>
                    </div>
                </div>
            </body>
            </html>
            "#,
            username, verification_link, verification_link
        );

        let email = Message::builder()
            .from(self.from_email.clone())
            .to(to_email.parse()?)
            .subject("Verify Your Email Address")
            .header(ContentType::TEXT_HTML)
            .body(html_body)?;

        self.mailer.send(&email)?;

        println!("Verification email sent to {}", to_email);
        println!("Verification link: {}", verification_link);

        Ok(())
    }
    pub async fn send_password_reset_email(
        &self,
        to_email: &str,
        username: &str,
        reset_token: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let base_url = env::var("BASE_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());
        let reset_link = format!("{}/api/auth/reset-password?token={}", base_url, reset_token);

        let html_body = format!(
            r#"
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background-color: #f8d7da; color: #721c24; padding: 20px; text-align: center; border-radius: 5px 5px 0 0; }}
                .content {{ background-color: #fff; padding: 30px; border: 1px solid #ddd; }}
                .button {{ display: inline-block; padding: 12px 24px; background-color: #dc3545; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }}
                .footer {{ text-align: center; margin-top: 20px; color: #666; font-size: 12px; }}
                .warning {{ background-color: #fff3cd; border-left: 4px solid #ffc107; padding: 12px; margin: 20px 0; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Password Reset Request</h1>
                </div>
                <div class="content">
                    <h2>Hi {}!</h2>
                    <p>We received a request to reset your password. If you didn't make this request, you can safely ignore this email.</p>
                    <p>To reset your password, click the button below:</p>
                    <div style="text-align: center;">
                        <a href="{}" class="button">Reset Password</a>
                    </div>
                    <p>Or copy and paste this link into your browser:</p>
                    <p style="background-color: #eee; padding: 10px; word-break: break-all;">{}</p>
                    <div class="warning">
                        <p><strong>⚠️ Security Notice:</strong></p>
                        <ul>
                            <li>This link will expire in 1 hour</li>
                            <li>The link can only be used once</li>
                            <li>If you didn't request this reset, someone may be trying to access your account</li>
                        </ul>
                    </div>
                    <p>After clicking the link, you'll be able to create a new password for your account.</p>
                </div>
                <div class="footer">
                    <p>© 2024 YourApp. All rights reserved.</p>
                    <p>If you have security concerns, please contact our support team immediately.</p>
                </div>
            </div>
        </body>
        </html>
        "#,
            username, reset_link, reset_link
        );

        let email = Message::builder()
            .from(self.from_email.clone())
            .to(to_email.parse()?)
            .subject("Reset Your Password")
            .header(ContentType::TEXT_HTML)
            .body(html_body)?;

        self.mailer.send(&email)?;

        println!("Password reset email sent to {}", to_email);
        println!("Reset link: {}", reset_link);

        Ok(())
    }
}
