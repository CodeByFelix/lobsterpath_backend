from fastapi import APIRouter, HTTPException, status, Depends, Request
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select, update, delete
from src import (
    User, UserRead, UserReturn, EmailValidationOtp, Token,
    UserCreate, UserLogin, LoginReturn, VerifyEmailRequest, SessionResponse
)
from src.utils import (
    hash_password, verify_password, get_current_user, create_token, 
    generate_otp, oauth_schema, cleanup_expired_tokens
)
from src.database import get_session
from src.email.send_email import send_email, load_otp_template
from src.middleware import (
    rate_limit_dependency, login_limiter, create_account_limiter,
    otp_request_limiter, otp_verify_limiter, get_client_ip
)
from datetime import datetime, timedelta, timezone
from user_agents import parse as parse_user_agent
from src.loggings import logging
import uuid

auth_router = APIRouter(prefix='/auth', tags=['auth'])


@auth_router.post(
    "/create", 
    status_code=status.HTTP_201_CREATED,
    summary="Create a new user account",
    description="Creates a new user account with a hashed password. Verifies that the email is not already in use.",
    responses={
        status.HTTP_401_UNAUTHORIZED: {"description": "Invalid Token or Token Expired"},
        status.HTTP_409_CONFLICT: {"description": "Email already exists"},
        status.HTTP_429_TOO_MANY_REQUESTS: {"description": "Rate limit exceeded"},
        status.HTTP_500_INTERNAL_SERVER_ERROR: {"description": "Database Error or Account creation failed"}
    }
)
async def create_account(
    request: Request, 
    user_in: UserCreate, 
    session: AsyncSession = Depends(get_session),
    _rate_limit = Depends(rate_limit_dependency(create_account_limiter))
):
    """
    Registers a new user in the database.
    
    Args:
        request (Request): Incoming request object.
        user_in (UserCreate): The user's registration details (email, password, name).
        session (AsyncSession): The database session.
        
    Returns:
        dict: A success message.

    Raises:
        HTTPException: 409 if email exists, 500 for database failures.
    """
    try:
        query = select(User).where(User.email == user_in.email)
        result = await session.execute(query)
        existing = result.one_or_none()
        
        if existing:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already exists")
        
        hashed_password = await hash_password(password=user_in.password)

        user = User(
            email=user_in.email,
            password=hashed_password,
            first_name=user_in.first_name,
            last_name=user_in.last_name
        )

        session.add(user)
        await session.commit()
        await session.refresh(user)
        return {'message': f"Account {user.email} created successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error creating account: {str(e)}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Account creation failed due to a server error.")


@auth_router.post(
    "/login", 
    response_model=LoginReturn, 
    status_code=status.HTTP_200_OK,
    summary="Login to user account",
    description="Authenticates a user via email and password, returning a JWT token for subsequent requests.",
    responses={
        status.HTTP_401_UNAUTHORIZED: {"description": "Wrong Email or Password or Invalid Token or Token Expired"},
        status.HTTP_429_TOO_MANY_REQUESTS: {"description": "Rate limit exceeded"},
        status.HTTP_500_INTERNAL_SERVER_ERROR: {"description": "Database Error"}
    }
)
async def login(
    request: Request, 
    user_in: UserLogin, 
    session: AsyncSession = Depends(get_session),
    _rate_limit = Depends(rate_limit_dependency(login_limiter))
):
    """
    Authenticates a user and generates a Bearer token.
    
    Args:
        request (Request): Incoming request object.
        user_in (UserLogin): The user's login credentials.
        session (AsyncSession): The database session.
        
    Returns:
        LoginReturn: The authenticated user profile and JWT token.

    Raises:
        HTTPException: 401 for invalid credentials, 500 for database failures.
    """
    try:
        query = select(User).where(User.email == user_in.email)
        result = await session.execute(query)
        existing = result.one_or_none()
        
        if not existing:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Wrong Email or Password")
        
        user = User.model_validate(existing[0])

        if not await verify_password(plain_password=user_in.password, hashed_password=user.password):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Wrong Email or Password")
        
        user_return = UserReturn.model_validate(user)

        # Parse device info from User-Agent header
        ua_string = request.headers.get("User-Agent", "")
        ua = parse_user_agent(ua_string)
        client_ip = get_client_ip(request)

        device_info = {
            "ip_address": client_ip,
            "os": f"{ua.os.family} {ua.os.version_string}".strip(),
            "browser": f"{ua.browser.family} {ua.browser.version_string}".strip(),
            "device_type": "Mobile" if ua.is_mobile else "Tablet" if ua.is_tablet else "Desktop",
        }

        # Passively clean up expired tokens for this user
        await cleanup_expired_tokens(user_id=str(user.id), session=session)

        token = await create_token(
            user_id=str(user.id), 
            expires=timedelta(hours=168), 
            session=session,
            **device_info
        )

        return LoginReturn(
            user=user_return,
            token=token,
            token_type="Bearer",
            message=f"Login to {user.email} successful"
        )
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error during login: {str(e)}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Login failed due to a server error.")


@auth_router.post(
    "/logout", 
    status_code=status.HTTP_200_OK,
    summary="Logout user",
    description="Logs the current user out by permanently invalidating their active session token.",
    responses={
        status.HTTP_401_UNAUTHORIZED: {"description": "Invalid Token or Token Expired"},
        status.HTTP_500_INTERNAL_SERVER_ERROR: {"description": "Database Error"}
    }
)
async def logout(
    session: AsyncSession = Depends(get_session),
    user: UserRead = Depends(get_current_user),
    credential: HTTPAuthorizationCredentials = Depends(oauth_schema)
):
    """
    Logs out the authenticated user by deleting their access token from the database.
    
    Args:
        session (AsyncSession): The database session.
        user (UserRead): The currently authenticated user.
        credential (HTTPAuthorizationCredentials): The token payload from the request header.
        
    Returns:
        dict: Success message.
    """
    try:
        token_str = credential.credentials
        query = select(Token).where(Token.token == token_str)
        
        result = await session.execute(query)
        token_record = result.scalar_one_or_none()
        
        if token_record:
            await session.delete(token_record)
            await session.commit()
            
        return {"message": "Successfully logged out"}
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error during logout: {str(e)}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Logout failed due to a server error.")


@auth_router.post(
    "/get-email-otp", 
    status_code=status.HTTP_200_OK,
    summary="Request Email Verification OTP",
    description="Generates an OTP and sends it to the user's registered email address for verification.",
    responses={
        status.HTTP_401_UNAUTHORIZED: {"description": "Invalid Token or Token Expired"},
        status.HTTP_429_TOO_MANY_REQUESTS: {"description": "Rate limit exceeded"},
        status.HTTP_500_INTERNAL_SERVER_ERROR: {"description": "Error storing or sending OTP"}
    }
)
async def get_email_otp(
    request: Request, 
    session: AsyncSession = Depends(get_session),
    user: UserRead = Depends(get_current_user),
    _rate_limit = Depends(rate_limit_dependency(otp_request_limiter))
):
    """
    Generates and sends a 6-digit OTP to the user's email.
    
    Args:
        request (Request): Incoming request object.
        session (AsyncSession): The database session.
        user (UserRead): The currently authenticated user.
        
    Returns:
        dict: A success message indicating the OTP was sent.
    """
    try:
        otp = await generate_otp(length=6)
        otp_data = EmailValidationOtp(
            user_id=user.id,
            email=user.email,
            otp=otp,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5)
        )

        body = load_otp_template(user_name=user.first_name, otp_code=otp)
        if await send_email(to_email=user.email, subject="Email Verification OTP", html_body=body):
            # Invalidate any previous OTPs for this user
            await session.execute(delete(EmailValidationOtp).where(EmailValidationOtp.user_id == user.id))
            session.add(otp_data)
            await session.commit()
            return {"message": "Email Verification OTP sent"}
        else:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to send verification email.")
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error sending OTP: {str(e)}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error while processing OTP.")


@auth_router.post(
    "/verify-email", 
    status_code=status.HTTP_200_OK,
    summary="Verify Email via OTP",
    description="Verifies the OTP sent to the user's email. If valid, marks the user's email as verified.",
    responses={
        status.HTTP_400_BAD_REQUEST: {"description": "Invalid OTP or OTP expired"},
        status.HTTP_401_UNAUTHORIZED: {"description": "Invalid Token or Token Expired"},
        status.HTTP_500_INTERNAL_SERVER_ERROR: {"description": "Database Error"}
    }
)
async def verify_email(
    request_body: VerifyEmailRequest, 
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: UserRead = Depends(get_current_user),
    _rate_limit = Depends(rate_limit_dependency(otp_verify_limiter))
):
    """
    Validates the submitted OTP against the database record to verify the user's email.
    
    Args:
        request_body (VerifyEmailRequest): The OTP submitted by the user.
        request (Request): Incoming request object.
        session (AsyncSession): The database session.
        user (UserRead): The currently authenticated user.
        
    Returns:
        dict: A success message if verification passes.
    """
    try:
        query = select(EmailValidationOtp).where(
            EmailValidationOtp.user_id == user.id,
            EmailValidationOtp.otp == request_body.otp
        )
        
        result = await session.execute(query)
        otp_record = result.scalar_one_or_none()
        
        if not otp_record:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid OTP")
        
        if otp_record.expires_at < datetime.now(timezone.utc):
            await session.delete(otp_record)
            await session.commit()
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="OTP has expired")
        
        update_query = update(User).where(User.id == user.id).values(email_verified=True)
        await session.execute(update_query)
        await session.delete(otp_record)
        await session.commit()
        
        return {'message': f"Email {user.email} verified successfully."}
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error verifying email: {str(e)}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Verification failed due to a database error.")


@auth_router.get(
    "/user-detail", 
    response_model=UserReturn, 
    status_code=status.HTTP_200_OK,
    summary="Get user details",
    description="Retrieves the profile details of the currently authenticated user.",
    responses={
        status.HTTP_401_UNAUTHORIZED: {"description": "Invalid Token or Token Expired"}
    }
)
async def get_user_details(user: UserRead = Depends(get_current_user)):
    """
    Returns the authenticated user's profile information.
    
    Args:
        user (UserRead): The currently authenticated user.
        
    Returns:
        UserReturn: The user's detailed profile.
    """
    return UserReturn.model_validate(user)


@auth_router.get(
    "/sessions",
    response_model=list[SessionResponse],
    status_code=status.HTTP_200_OK,
    summary="Get all active sessions",
    description="Returns a list of all active login sessions for the authenticated user, including device details.",
    responses={
        status.HTTP_401_UNAUTHORIZED: {"description": "Invalid Token or Token Expired"},
        status.HTTP_500_INTERNAL_SERVER_ERROR: {"description": "Database Error"}
    }
)
async def get_sessions(
    session: AsyncSession = Depends(get_session),
    user: UserRead = Depends(get_current_user),
    credential: HTTPAuthorizationCredentials = Depends(oauth_schema)
):
    """
    Returns all active (non-expired) sessions for the current user.

    Args:
        session (AsyncSession): The database session.
        user (UserRead): The authenticated user making the request.
        credential (HTTPAuthorizationCredentials): The token credentials of the current request.

    Returns:
        List[SessionResponse]: A list of active sessions with device and location metadata.

    Raises:
        HTTPException: 401 if unauthorized, 500 if database retrieval fails.
    """
    try:
        current_token = credential.credentials
        query = select(Token).where(
            Token.user_id == user.id,
            Token.exp > datetime.now(timezone.utc)
        ).order_by(Token.created_at.desc())

        result = await session.execute(query)
        tokens = result.scalars().all()

        return [
            SessionResponse(
                id=t.id,
                ip_address=t.ip_address,
                os=t.os,
                browser=t.browser,
                device_type=t.device_type,
                created_at=t.created_at,
                is_current_session=(t.token == current_token)
            ) for t in tokens
        ]
    except Exception as e:
        logging.error(f"Error fetching sessions: {str(e)}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to retrieve active sessions.")


@auth_router.delete(
    "/sessions/{session_id}",
    status_code=status.HTTP_200_OK,
    summary="Revoke a specific session",
    description="Logs out a specific device by deleting its session token. Cannot revoke the current session.",
    responses={
        status.HTTP_400_BAD_REQUEST: {"description": "Cannot revoke current session. Use /logout instead."},
        status.HTTP_401_UNAUTHORIZED: {"description": "Invalid Token or Token Expired"},
        status.HTTP_404_NOT_FOUND: {"description": "Session not found"},
        status.HTTP_500_INTERNAL_SERVER_ERROR: {"description": "Database Error"}
    }
)
async def revoke_session(
    session_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: UserRead = Depends(get_current_user),
    credential: HTTPAuthorizationCredentials = Depends(oauth_schema)
):
    """
    Revokes a specific session by its ID. 
    Note: You cannot revoke the session you are currently using through this endpoint.

    Args:
        session_id (uuid.UUID): The ID of the session/token to revoke.
        session (AsyncSession): The database session.
        user (UserRead): The authenticated user owning the session.
        credential (HTTPAuthorizationCredentials): The credentials of the current request.

    Returns:
        dict: A success confirmation message.

    Raises:
        HTTPException: 404 if the session isn't found, 400 if trying to revoke current session, 500 on failure.
    """
    try:
        current_token = credential.credentials
        query = select(Token).where(Token.id == session_id, Token.user_id == user.id)

        result = await session.execute(query)
        token_record = result.scalar_one_or_none()

        if not token_record:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")

        if token_record.token == current_token:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot revoke current session. Use /logout instead.")

        await session.delete(token_record)
        await session.commit()
        return {"message": "Session revoked successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error revoking session: {str(e)}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to revoke session.")


@auth_router.delete(
    "/sessions",
    status_code=status.HTTP_200_OK,
    summary="Logout from all devices",
    description="Revokes all active sessions for the authenticated user, including the current one.",
    responses={
        status.HTTP_401_UNAUTHORIZED: {"description": "Invalid Token or Token Expired"},
        status.HTTP_500_INTERNAL_SERVER_ERROR: {"description": "Database Error"}
    }
)
async def logout_all_devices(
    session: AsyncSession = Depends(get_session),
    user: UserRead = Depends(get_current_user)
):
    """
    Deletes all token records for the current user across all devices.

    Args:
        session (AsyncSession): The database session.
        user (UserRead): The authenticated user performing the logout.

    Returns:
        dict: A success confirmation message.

    Raises:
        HTTPException: 401 if unauthorized, 500 if the bulk deletion fails.
    """
    try:
        await session.execute(delete(Token).where(Token.user_id == user.id))
        await session.commit()
        return {"message": "Successfully logged out from all devices"}
    except Exception as e:
        logging.error(f"Error revoking all sessions: {str(e)}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to revoke all sessions.")