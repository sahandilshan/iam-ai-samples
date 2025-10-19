"""
 Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com). All Rights Reserved.

  This software is the property of WSO2 LLC. and its suppliers, if any.
  Dissemination of any information or reproduction of any material contained
  herein is strictly forbidden, unless permitted by WSO2 in accordance with
  the WSO2 Commercial License available at http://wso2.com/licenses.
  For specific language governing the permissions and limitations under
  this license, please see the license as well as any agreement you've
  entered into with WSO2 governing the purchase of this software and any
"""

"""
MCP Server using FastMCP with OAuth 2.1 Provider
Simplified version with minimal configuration (3 environment variables)
"""

import os
from dotenv import load_dotenv
from pydantic import AnyHttpUrl
import logging
import jwt
from jwt import PyJWKClient
from typing import Optional
from fastapi.middleware.cors import CORSMiddleware

from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SimplifiedTokenVerifier(TokenVerifier):
    """
    Simplified JWT token verifier using JWKS
    Returns None for invalid tokens to allow unauthenticated access
    """

    def __init__(self, jwks_url: str, issuer: str, client_id: str):
        self.jwks_url = jwks_url
        self.issuer = issuer
        self.client_id = client_id

        # Initialize JWKS client with caching
        self.jwks_client = PyJWKClient(
            self.jwks_url,
            cache_keys=True,
            max_cached_keys=10,
            cache_jwk_set=True
        )

        logger.info(f"Token verifier initialized")
        logger.info(f"Issuer: {issuer}")

    async def verify_token(self, token: str) -> AccessToken | None:
        """Verify JWT token and return AccessToken if valid, None otherwise"""
        if not token or token.strip() == "":
            logger.info("ℹ️  No token provided - allowing unauthenticated access")
            return None

        try:
            # Get signing key from JWKS
            signing_key = self.jwks_client.get_signing_key_from_jwt(token)

            # Decode and verify token
            payload = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=self.client_id,
                issuer=self.issuer,
                options={
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_aud": True,
                    "verify_iss": True
                }
            )

            # Extract information
            expires_at = payload.get("exp")
            subject = payload.get("sub")
            audience = payload.get("aud")

            # Extract scopes (try common claim names)
            scopes = []
            for claim in ["scope", "scp", "scopes"]:
                if claim in payload:
                    value = payload[claim]
                    scopes = value.split() if isinstance(value, str) else (value if isinstance(value, list) else [])
                    break

            client_id = audience if isinstance(audience, str) else (audience[0] if isinstance(audience, list) and audience else self.client_id)

            logger.info(f"✅ Token validated for subject: {subject}")

            return AccessToken(
                token=token,
                client_id=client_id,
                scopes=scopes,
                expires_at=str(expires_at) if expires_at else None
            )

        except jwt.ExpiredSignatureError:
            logger.warning("❌ Token expired - allowing unauthenticated access")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"❌ Invalid token: {e} - allowing unauthenticated access")
            return None
        except Exception as e:
            logger.error(f"❌ Token validation error: {e} - allowing unauthenticated access")
            return None


# ======================
# Environment Configuration (Only 3 variables needed!)
# ======================

AUTH_ISSUER = os.getenv("AUTH_ISSUER")
CLIENT_ID = os.getenv("CLIENT_ID")
JWKS_URL = os.getenv("JWKS_URL")

# Validate required environment variables
if not all([AUTH_ISSUER, CLIENT_ID, JWKS_URL]):
    raise ValueError("Missing required environment variables: AUTH_ISSUER, CLIENT_ID, or JWKS_URL")

# Optional: Server URL (defaults to localhost:8000)
MCP_SERVER_URL = os.getenv("MCP_SERVER_URL", "http://localhost:8000")

logger.info("=" * 60)
logger.info("MCP Server Configuration")
logger.info("=" * 60)
logger.info(f"Server URL: {MCP_SERVER_URL}")
logger.info(f"Auth Issuer: {AUTH_ISSUER}")
logger.info(f"Client ID: {CLIENT_ID}")
logger.info("=" * 60)

# ======================
# Create FastMCP Instance
# ======================

mcp = FastMCP(
    "Weather Service",
    token_verifier=SimplifiedTokenVerifier(JWKS_URL, AUTH_ISSUER, CLIENT_ID),
    auth=AuthSettings(
        issuer_url=AnyHttpUrl(AUTH_ISSUER),
        resource_server_url=AnyHttpUrl(MCP_SERVER_URL),
        required_scopes=["openid", "email", "profile"]
    )
)

# ======================
# Configure CORS
# ======================

streamable_app = mcp.streamable_http_app()

streamable_app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["mcp-session-id"],
)

logger.info("✅ CORS middleware configured")

# ======================
# Helper Functions
# ======================

def get_current_user_token():
    """Get the current user's access token from request context"""
    try:
        context = mcp.get_context()
        if not context or not context.request_context or not context.request_context.request:
            return None

        user = context.request_context.request.user
        if not user or not user.access_token:
            return None

        return user.access_token
    except Exception as e:
        logger.error(f"Error getting user token: {e}")
        return None


def check_scope(required_scope: str) -> tuple[bool, Optional[str], Optional[list[str]]]:
    """
    Check if the current user has the required scope
    Returns: (has_scope, error_message, user_scopes)
    """
    access_token = get_current_user_token()
    if not access_token:
        return False, f"This tool requires authentication with '{required_scope}' scope", None

    user_scopes = access_token.scopes or []

    if required_scope not in user_scopes:
        return False, f"Missing required scope: '{required_scope}'. Your scopes: {user_scopes}", user_scopes

    return True, None, user_scopes


# ======================
# Define MCP Tools
# ======================

@mcp.tool()
async def get_weather(city: str = "London") -> dict[str, str]:
    """
    Get weather data for a city
    This tool works without authentication.
    """
    logger.info(f"🌤️  Getting weather for: {city}")
    return {
        "city": city,
        "temperature": "22°C",
        "condition": "Partly cloudy",
        "humidity": "65%",
    }


@mcp.tool()
async def get_server_info() -> dict[str, str]:
    """
    Get information about the MCP server
    This tool works without authentication.
    """
    logger.info("ℹ️  Getting server information")

    access_token = get_current_user_token()
    is_authenticated = access_token is not None

    return {
        "server_name": "Weather Service MCP Server",
        "version": "1.0.0",
        "authentication": "enabled",
        "transport": "streamable-http",
        "your_status": "authenticated" if is_authenticated else "unauthenticated",
    }


@mcp.tool()
async def get_email() -> dict[str, str]:
    """
    Get the email address of the authenticated user
    Requires authentication with 'email' scope
    """
    logger.info("📧 Getting user email")

    has_scope, error_msg, _ = check_scope("email")
    if not has_scope:
        logger.warning(f"⚠️  {error_msg}")
        return {
            "status": "error",
            "error": error_msg,
        }

    access_token = get_current_user_token()
    if not access_token:
        return {
            "status": "error",
            "error": "Failed to retrieve access token"
        }

    try:
        decoded = jwt.decode(access_token.token, options={"verify_signature": False})
        email = decoded.get("email")
        email_verified = decoded.get("email_verified", False)

        if not email:
            return {
                "status": "error",
                "error": "Email not found in token claims"
            }

        logger.info(f"✅ Email retrieved: {email}")

        return {
            "status": "success",
            "email": email,
            "email_verified": str(email_verified),
        }

    except Exception as e:
        logger.error(f"❌ Error extracting email: {e}")
        return {
            "status": "error",
            "error": f"Failed to extract email from token: {str(e)}"
        }


@mcp.tool()
async def get_name() -> dict[str, str]:
    """
    Get the name of the authenticated user
    Requires authentication with 'profile' scope
    """
    logger.info("👤 Getting user name")

    has_scope, error_msg, _ = check_scope("profile")
    if not has_scope:
        logger.warning(f"⚠️  {error_msg}")
        return {
            "status": "error",
            "error": error_msg,
        }

    access_token = get_current_user_token()
    if not access_token:
        return {
            "status": "error",
            "error": "Failed to retrieve access token"
        }

    try:
        decoded = jwt.decode(access_token.token, options={"verify_signature": False})

        name = decoded.get("name")
        given_name = decoded.get("given_name")
        family_name = decoded.get("family_name")
        preferred_username = decoded.get("preferred_username")

        response = {"status": "success"}

        if name:
            response["name"] = name
        if given_name:
            response["given_name"] = given_name
        if family_name:
            response["family_name"] = family_name
        if preferred_username:
            response["preferred_username"] = preferred_username

        if not any([name, given_name, family_name, preferred_username]):
            return {
                "status": "error",
                "error": "No name information found in token claims"
            }

        logger.info(f"✅ Name retrieved: {name or given_name or preferred_username}")

        return response

    except Exception as e:
        logger.error(f"❌ Error extracting name: {e}")
        return {
            "status": "error",
            "error": f"Failed to extract name from token: {str(e)}"
        }


# ======================
# Run Server
# ======================

if __name__ == "__main__":
    import uvicorn

    logger.info("🚀 Starting MCP Server with OAuth 2.1 authentication")
    logger.info(f"   Transport: streamable-http")
    logger.info(f"   Host: 127.0.0.1")
    logger.info(f"   Port: 8000")
    logger.info("=" * 60)

    uvicorn.run(streamable_app, host="127.0.0.1", port=8000)
