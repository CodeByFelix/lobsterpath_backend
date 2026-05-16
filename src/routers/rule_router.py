from fastapi import APIRouter, Depends, status, HTTPException
from src.schema import RuleBankResponse, RuleInfo, LLMProviderList, LLMProvider, ModelListResponse
from src.rule_bank import RULE_BANK, PROVIDER_LIST, MODEL_BANK
from src.utils import get_current_user
from src.model import UserRead
from src.loggings import logging

rule_router = APIRouter(prefix="/rules", tags=["Rules"])

@rule_router.get(
    "/providers",
    response_model=LLMProviderList,
    status_code=status.HTTP_200_OK,
    summary="List available LLM providers",
    description="Fetches a list of pre-configured OpenAI-compatible LLM providers and their base URLs supported by the AI-SOC gateway.",
    responses={
        status.HTTP_401_UNAUTHORIZED: {"description": "Invalid Token or Token Expired"},
        status.HTTP_500_INTERNAL_SERVER_ERROR: {"description": "Failed to retrieve the provider registry"}
    }
)
async def list_llm_providers(current_user: UserRead = Depends(get_current_user)):
    """
    Returns a curated list of LLM providers.

    Args:
        current_user (UserRead): The authenticated user making the request.

    Returns:
        LLMProviderList: A list of supported LLM providers and their metadata.

    Raises:
        HTTPException: 500 if an internal error occurs.
    """
    try:
        providers = [LLMProvider(**p) for p in PROVIDER_LIST]
        return LLMProviderList(providers=providers)
    except Exception as e:
        logging.error(f"Error listing providers: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve LLM providers."
        )

@rule_router.get(
    "/", 
    response_model=RuleBankResponse,
    status_code=status.HTTP_200_OK,
    summary="List all available security rules",
    description="Fetches the full bank of Deep Prompt Inspection (DPI) rules available to be enabled for projects.",
    responses={
        status.HTTP_401_UNAUTHORIZED: {"description": "Invalid Token or Token Expired"},
        status.HTTP_500_INTERNAL_SERVER_ERROR: {"description": "Internal server error while processing the rule bank"}
    }
)
async def list_available_rules(current_user: UserRead = Depends(get_current_user)):
    """
    Returns a structured list of ingress and egress rules from the Master Rule Bank.

    Args:
        current_user (UserRead): The authenticated user making the request.

    Returns:
        RuleBankResponse: A dictionary containing available ingress and egress rules with their IDs and descriptions.

    Raises:
        HTTPException: 401 if unauthorized, 500 if the master bank fails to load.
    """
    try:
        ingress = [
            RuleInfo(id=k, name=v["name"], description=v["description"])
            for k, v in RULE_BANK["ingress"].items()
        ]
        egress = [
            RuleInfo(id=k, name=v["name"], description=v["description"])
            for k, v in RULE_BANK["egress"].items()
        ]
        return RuleBankResponse(ingress=ingress, egress=egress)
    except Exception as e:
        logging.error(f"Error listing rules: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while retrieving the rules from the master bank."
        )

@rule_router.get(
    "/models/{provider_name}",
    response_model=ModelListResponse,
    status_code=status.HTTP_200_OK,
    summary="List available models for a provider",
    description="Returns a curated list of stable model IDs for a given LLM provider. This helps prevent configuration errors by providing known-good model names.",
    responses={
        status.HTTP_404_NOT_FOUND: {"description": "The specified provider name was not found in our curated list"},
        status.HTTP_401_UNAUTHORIZED: {"description": "Invalid Token or Token Expired"},
        status.HTTP_500_INTERNAL_SERVER_ERROR: {"description": "Failed to retrieve the model list"}
    }
)
async def list_provider_models(
    provider_name: str,
    current_user: UserRead = Depends(get_current_user)
):
    """
    Returns a list of curated models for a specific provider.

    Args:
        provider_name (str): The name of the provider (e.g., 'OpenAI', 'Groq').
        current_user (UserRead): The authenticated user making the request.

    Returns:
        ModelListResponse: A list of stable model IDs for the requested provider.

    Raises:
        HTTPException: 404 if the provider is unknown, 401 if unauthorized.
    """
    # Normalize provider name for lookup
    normalized_name = provider_name.strip()
    
    # Try exact match or case-insensitive match
    models = MODEL_BANK.get(normalized_name)
    if not models:
        # Fallback to case-insensitive check
        for key in MODEL_BANK.keys():
            if key.lower() == normalized_name.lower():
                models = MODEL_BANK[key]
                normalized_name = key
                break
    
    if not models:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Provider '{provider_name}' not found in our curated list. Available providers are: {', '.join(MODEL_BANK.keys())}"
        )
        
    return ModelListResponse(provider=normalized_name, models=models)
