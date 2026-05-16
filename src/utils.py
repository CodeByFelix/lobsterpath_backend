from passlib.context import CryptContext
from jose import jwt, JWTError, ExpiredSignatureError
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi import HTTPException, status, Depends
from datetime import datetime, timedelta, timezone
from sqlmodel import select, delete
from sqlalchemy.ext.asyncio import AsyncSession
from src.database import get_session
from src.model import User, UserRead, Token, Project, APIKey, Policy
from src.settings import settings
from src.loggings import logging
import random
import secrets
import hashlib
from src.rule_bank import RULE_BANK
from typing import List

password_context = CryptContext (schemes=['bcrypt'], deprecated='auto')
secret_key = settings.SECRET_KEY
algorithm = settings.ALGORITHM

oauth_schema = HTTPBearer ()


async def hash_password (password: str) -> str:
    return password_context.hash (password)

async def verify_password (plain_password: str, hashed_password: str) -> bool:
    return password_context.verify (plain_password, hashed_password)

async def create_token (user_id: str, expires: timedelta = None, session: AsyncSession = None,
                        ip_address: str = None, os: str = None, browser: str = None, 
                        device_type: str = None) -> str:
    ex = datetime.now (timezone.utc) + (expires or timedelta (hours=168))
    data = {'id': user_id, 'exp': ex}
    token = jwt.encode (claims=data, key=secret_key, algorithm=algorithm)
    token_entry = Token(
        user_id=user_id, 
        token=token, 
        exp=ex,
        ip_address=ip_address,
        os=os,
        browser=browser,
        device_type=device_type
    )
    try:
        session.add (token_entry)
        await session.commit ()
        return token
    except:
        logging.exception ("DB Error")
        raise HTTPException (status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Unable to Connect to the DB")


async def cleanup_expired_tokens (user_id: str, session: AsyncSession) -> None:
    """Remove all expired tokens for the given user."""
    try:
        cleanup_query = delete (Token).where (
            Token.user_id == user_id,
            Token.exp < datetime.now (timezone.utc)
        )
        await session.execute (cleanup_query)
        await session.commit ()
    except:
        logging.exception ("Error cleaning up expired tokens")
    

async def delete_token_record (token_record: Token, session: AsyncSession = None):
    await session.delete (token_record)
    await session.commit ()

async def get_current_user (credential: HTTPAuthorizationCredentials = Depends (oauth_schema),
                            session: AsyncSession = Depends (get_session)) -> UserRead:
    token = credential.credentials
    credential_exception = HTTPException (status_code=status.HTTP_401_UNAUTHORIZED,
                                          detail="Invalid Token",
                                          headers={'WWW-Authenticate': "Bearer"})
    credential_expired = HTTPException (status_code=status.HTTP_401_UNAUTHORIZED,
                                         detail="Token Expired",
                                         headers={'WWW-Authenticate': "Bearer"})
    
    query = select (Token).where (Token.token == token)
    try:
        result = await session.execute (query)
        token_record = result.scalar_one_or_none ()
        
    except:
        logging.exception ("DB Error")
        raise HTTPException (status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Unable to Connect to the DB")
    else:
        if not token_record:
            raise credential_exception
        
        try:
            payload = jwt.decode (token=token, key=secret_key, algorithms=algorithm)
            user_id = payload.get ('id', None)
            
        except JWTError:
            await delete_token_record (token_record=token_record, session=session)
            raise credential_exception
        except ExpiredSignatureError:
            await delete_token_record (token_record=token_record, session=session)
            raise credential_expired
        else:
            if user_id is None:
                await delete_token_record (token_record=token_record, session=session)
                raise credential_exception
            
            try:
                query = select (User).where (User.id == user_id)
                result = await session.execute (query)
                user = result.one_or_none ()
            except:
                raise HTTPException (status_code=400, detail="DB Connection Error")
            if not user:
                raise credential_exception
            
            return UserRead.model_validate (user[0], from_attributes=True)


async def generate_otp (length: int = 6) -> str:
    return ''.join (str(random.randint(0, 9)) for _ in range (length))


def generate_api_key() -> str:
    """
    Generate a cryptographically secure random API key.
    Uses 48 bytes of entropy, resulting in a ~64 character string.
    """
    return f"soc_live_{secrets.token_urlsafe(48)}"


def hash_api_key(api_key: str) -> str:
    """Hash the API key using SHA256."""
    return hashlib.sha256(api_key.encode()).hexdigest()


async def get_project_by_api_key(
    credential: HTTPAuthorizationCredentials = Depends(oauth_schema),
    session: AsyncSession = Depends(get_session)
) -> dict:
    """Validate API Key and return the associated project and policy."""
    api_key = credential.credentials
    key_hash = hash_api_key(api_key)
    
    # Join APIKey with Project and Policy
    query = select(APIKey, Project, Policy).join(
        Project, APIKey.project_id == Project.id
    ).outerjoin(
        Policy, Project.id == Policy.project_id
    ).where(
        APIKey.key_hash == key_hash,
        APIKey.is_active == True,
        Project.is_active == True
    )
    
    try:
        result = await session.execute(query)
        record = result.first()
        
        if not record:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid SOC API Key",
                headers={'WWW-Authenticate': "Bearer"}
            )
        
        api_key_obj, project_obj, policy_obj = record
        return {
            "api_key": api_key_obj,
            "project": project_obj,
            "policy": policy_obj
        }
    except HTTPException:
        raise
    except Exception as e:
        logging.exception(f"DB Error in API key validation: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="DB Error"
        )


def assemble_lobstertrap_policy(project_name: str, enabled_ingress: List[str], enabled_egress: List[str]):
    """Construct a full Go-compatible policy object from a list of rule names."""
    policy = {
        "version": "1.0",
        "policy_name": project_name,
        "default_action": "ALLOW",
        "ingress_rules": [RULE_BANK["ingress"][name] for name in enabled_ingress if name in RULE_BANK["ingress"]],
        "egress_rules": [RULE_BANK["egress"][name] for name in enabled_egress if name in RULE_BANK["egress"]],
        "rate_limits": RULE_BANK["defaults"]["rate_limits"],
        "network": RULE_BANK["defaults"]["network"],
        "filesystem": RULE_BANK["defaults"]["filesystem"]
    }
    return policy
