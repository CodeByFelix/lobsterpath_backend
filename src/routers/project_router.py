from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select, delete
from typing import List, Optional
import uuid
from datetime import datetime, timezone

from src.database import get_session
from src.model import Project, APIKey, Policy, UserRead, AuditEvent
from src.schema import ProjectCreate, ProjectUpdate, ProjectRead, APIKeyCreate, APIKeyRead, APIKeyCreated, PolicySelectionUpdate, PolicyRead, AuditEventRead, ReportRequest
from src.utils import get_current_user, generate_api_key, hash_api_key
from src.routers.utils import generate_comprehensive_report
from src.loggings import logging

project_router = APIRouter(prefix="/projects", tags=["Projects"])

@project_router.post(
    "/", 
    response_model=ProjectRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new project",
    description="Initializes a new AI security project for the authenticated user and sets up a default empty policy.",
    responses={
        status.HTTP_401_UNAUTHORIZED: {"description": "Invalid Token or Token Expired"},
        status.HTTP_500_INTERNAL_SERVER_ERROR: {"description": "Database error during project creation"}
    }
)
async def create_project(
    project_data: ProjectCreate,
    current_user: UserRead = Depends(get_current_user),
    session: AsyncSession = Depends(get_session)
):
    """
    Registers a new project and initializes its security policy.

    Args:
        project_data (ProjectCreate): The data required to create a project (e.g., name).
        current_user (UserRead): The authenticated user creating the project.
        session (AsyncSession): The database session.

    Returns:
        ProjectRead: The newly created project object.

    Raises:
        HTTPException: 401 if unauthorized, 500 if database creation fails.
    """
    try:
        project = Project(
            name=project_data.name,
            user_id=current_user.id
        )
        session.add(project)
        await session.commit()
        await session.refresh(project)
        
        # Create a default empty policy selection for the project
        policy = Policy(project_id=project.id, selection_json={"enabled_ingress": [], "enabled_egress": []})
        session.add(policy)
        await session.commit()
        
        return project
    except Exception as e:
        logging.error(f"Error creating project: {str(e)}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create project.")

@project_router.get(
    "/", 
    response_model=List[ProjectRead],
    summary="List all projects",
    description="Returns all AI security projects owned by the authenticated user.",
    responses={
        status.HTTP_401_UNAUTHORIZED: {"description": "Invalid Token or Token Expired"},
        status.HTTP_500_INTERNAL_SERVER_ERROR: {"description": "Database error"}
    }
)
async def list_projects(
    current_user: UserRead = Depends(get_current_user),
    session: AsyncSession = Depends(get_session)
):
    """
    Fetches all projects for the current user.

    Args:
        current_user (UserRead): The authenticated user making the request.
        session (AsyncSession): The database session.

    Returns:
        List[ProjectRead]: A list of all projects belonging to the user.

    Raises:
        HTTPException: 401 if unauthorized, 500 if the query fails.
    """
    try:
        query = select(Project).where(Project.user_id == current_user.id)
        result = await session.execute(query)
        return result.scalars().all()
    except Exception as e:
        logging.error(f"Error listing projects: {str(e)}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to retrieve projects.")

@project_router.get(
    "/{project_id}", 
    response_model=ProjectRead,
    summary="Get project details",
    description="Retrieves the full configuration of a specific project, including its current alert settings and active status.",
    responses={
        status.HTTP_404_NOT_FOUND: {"description": "Project not found or user does not have access"},
        status.HTTP_401_UNAUTHORIZED: {"description": "Invalid Token or Token Expired"},
        status.HTTP_500_INTERNAL_SERVER_ERROR: {"description": "Database retrieval error"}
    }
)
async def get_project(
    project_id: uuid.UUID,
    current_user: UserRead = Depends(get_current_user),
    session: AsyncSession = Depends(get_session)
):
    """
    Retrieves detailed configuration for a specific project.

    Args:
        project_id (uuid.UUID): The unique identifier of the project.
        current_user (UserRead): The authenticated user making the request.
        session (AsyncSession): The database session.

    Returns:
        ProjectRead: The requested project details.

    Raises:
        HTTPException: 404 if not found, 401 if unauthorized, 500 on database failure.
    """
    try:
        query = select(Project).where(Project.id == project_id, Project.user_id == current_user.id)
        result = await session.execute(query)
        project = result.scalar_one_or_none()
        if not project:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
        return project
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error getting project: {str(e)}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to retrieve project.")

@project_router.patch(
    "/{project_id}", 
    response_model=ProjectRead,
    summary="Update project details",
    description="Updates project settings, including alert configuration and name.",
    responses={
        status.HTTP_401_UNAUTHORIZED: {"description": "Invalid Token or Token Expired"},
        status.HTTP_404_NOT_FOUND: {"description": "Project not found"}
    }
)
async def update_project(
    project_id: uuid.UUID,
    project_data: ProjectUpdate,
    current_user: UserRead = Depends(get_current_user),
    session: AsyncSession = Depends(get_session)
):
    """
    Updates specific fields of an existing project.

    Args:
        project_id (uuid.UUID): ID of the project to update.
        project_data (ProjectUpdate): Partial data to update (name, alert settings, etc.).
        current_user (UserRead): The authenticated user making the request.
        session (AsyncSession): The database session.

    Returns:
        ProjectRead: The updated project object.

    Raises:
        HTTPException: 404 if project not found, 401 if unauthorized, 500 on failure.
    """
    try:
        query = select(Project).where(Project.id == project_id, Project.user_id == current_user.id)
        result = await session.execute(query)
        project = result.scalar_one_or_none()
        if not project:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
        
        # Update only provided fields
        update_data = project_data.model_dump(exclude_unset=True)
        for key, value in update_data.items():
            setattr(project, key, value)
            
        session.add(project)
        await session.commit()
        await session.refresh(project)
        return project
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error updating project: {str(e)}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to update project.")

@project_router.post(
    "/{project_id}/toggle", 
    response_model=ProjectRead,
    summary="Toggle project active status",
    description="Flips the current active status of the project. Useful for UI toggle buttons.",
    responses={
        status.HTTP_404_NOT_FOUND: {"description": "Project not found"},
        status.HTTP_401_UNAUTHORIZED: {"description": "Invalid Token or Token Expired"},
        status.HTTP_500_INTERNAL_SERVER_ERROR: {"description": "Failed to toggle status"}
    }
)
async def toggle_project(
    project_id: uuid.UUID,
    current_user: UserRead = Depends(get_current_user),
    session: AsyncSession = Depends(get_session)
):
    """
    Toggles the is_active status of a specific project.

    Args:
        project_id (uuid.UUID): ID of the project to toggle.
        current_user (UserRead): The authenticated user making the request.
        session (AsyncSession): The database session.

    Returns:
        ProjectRead: The updated project object with the new status.

    Raises:
        HTTPException: 404 if not found, 500 on database failure.
    """
    try:
        query = select(Project).where(Project.id == project_id, Project.user_id == current_user.id)
        result = await session.execute(query)
        project = result.scalar_one_or_none()
        if not project:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
        
        project.is_active = not project.is_active
            
        session.add(project)
        await session.commit()
        await session.refresh(project)
        return project
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error toggling project: {str(e)}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to toggle project status.")

@project_router.post(
    "/api-keys", 
    response_model=APIKeyCreated,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new API Key",
    description="Generates a new API Key for a project. The plain text key is returned only once.",
    responses={
        status.HTTP_404_NOT_FOUND: {"description": "Project not found"},
        status.HTTP_401_UNAUTHORIZED: {"description": "Invalid Token or Token Expired"},
        status.HTTP_500_INTERNAL_SERVER_ERROR: {"description": "Database error"}
    }
)
async def create_api_key(
    key_data: APIKeyCreate,
    current_user: UserRead = Depends(get_current_user),
    session: AsyncSession = Depends(get_session)
):
    """
    Generates and stores a hashed API key for a project.
    Returns the plain text key once to the user.

    Args:
        key_data (APIKeyCreate): Data for the new key (name, project_id, provider details).
        current_user (UserRead): The authenticated user owning the project.
        session (AsyncSession): The database session.

    Returns:
        APIKeyCreated: The key metadata and the ONE-TIME plain text key.

    Raises:
        HTTPException: 404 if the project is invalid, 500 on generation failure.
    """
    try:
        # Verify project belongs to user
        query = select(Project).where(Project.id == key_data.project_id, Project.user_id == current_user.id)
        result = await session.execute(query)
        project = result.scalar_one_or_none()
        if not project:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invalid Project Id")
        
        plain_key = generate_api_key()
        key_hash = hash_api_key(plain_key)
        
        api_key = APIKey(
            name=key_data.name,
            key_hash=key_hash,
            project_id=project.id,
            backend_url=key_data.backend_url,
            backend_api_key=key_data.backend_api_key
        )
        session.add(api_key)
        await session.commit()
        await session.refresh(api_key)
        
        # Return plain key only once by injecting it into the response dictionary
        key_data_dict = api_key.model_dump()
        key_data_dict["api_key"] = plain_key
        return APIKeyCreated.model_validate(key_data_dict)
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error creating API Key: {str(e)}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create API key.")

@project_router.get(
    "/api-keys/{project_id}", 
    response_model=List[APIKeyRead],
    summary="List API Keys for a project",
    responses={
        status.HTTP_404_NOT_FOUND: {"description": "Project not found"},
        status.HTTP_401_UNAUTHORIZED: {"description": "Invalid Token or Token Expired"},
        status.HTTP_500_INTERNAL_SERVER_ERROR: {"description": "Database error"}
    }
)
async def list_api_keys(
    project_id: uuid.UUID,
    current_user: UserRead = Depends(get_current_user),
    session: AsyncSession = Depends(get_session)
):
    """
    Lists all API keys associated with a specific project.

    Args:
        project_id (uuid.UUID): ID of the project.
        current_user (UserRead): The authenticated user making the request.
        session (AsyncSession): The database session.

    Returns:
        List[APIKeyRead]: A list of API key metadata (hashes are excluded).

    Raises:
        HTTPException: 404 if project not found, 500 on database failure.
    """
    try:
        # Verify project belongs to user
        query = select(Project).where(Project.id == project_id, Project.user_id == current_user.id)
        result = await session.execute(query)
        if not result.scalar_one_or_none():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
        
        query = select(APIKey).where(APIKey.project_id == project_id)
        result = await session.execute(query)
        return result.scalars().all()
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error listing API Keys: {str(e)}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to retrieve API keys.")

@project_router.get(
    "/policies/{project_id}", 
    response_model=PolicyRead,
    summary="Get project security policy",
    responses={
        status.HTTP_401_UNAUTHORIZED: {"description": "Invalid Token or Token Expired"},
        status.HTTP_404_NOT_FOUND: {"description": "Project or Policy not found"}
    }
)
async def get_policy(
    project_id: uuid.UUID,
    current_user: UserRead = Depends(get_current_user),
    session: AsyncSession = Depends(get_session)
):
    """
    Retrieves the enabled rules for a specific project.

    Args:
        project_id (uuid.UUID): ID of the project.
        current_user (UserRead): The authenticated user making the request.
        session (AsyncSession): The database session.

    Returns:
        PolicyRead: The project's current policy configuration.

    Raises:
        HTTPException: 404 if not found, 500 on database failure.
    """
    try:
        query = select(Project).where(Project.id == project_id, Project.user_id == current_user.id)
        result = await session.execute(query)
        if not result.scalar_one_or_none():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
        
        query = select(Policy).where(Policy.project_id == project_id)
        result = await session.execute(query)
        policy = result.scalar_one_or_none()
        if not policy:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Policy not found")
        return policy
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error getting policy: {str(e)}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to retrieve policy.")

@project_router.put(
    "/policies/{project_id}", 
    response_model=PolicyRead,
    summary="Update project security policy",
    responses={
        status.HTTP_401_UNAUTHORIZED: {"description": "Invalid Token or Token Expired"},
        status.HTTP_404_NOT_FOUND: {"description": "Project not found"}
    }
)
async def update_policy(
    project_id: uuid.UUID,
    policy_data: PolicySelectionUpdate,
    current_user: UserRead = Depends(get_current_user),
    session: AsyncSession = Depends(get_session)
):
    """
    Updates the list of enabled rules for a project.

    Args:
        project_id (uuid.UUID): ID of the project.
        policy_data (PolicySelectionUpdate): The new selection of ingress/egress rules.
        current_user (UserRead): The authenticated user making the request.
        session (AsyncSession): The database session.

    Returns:
        PolicyRead: The updated policy object.

    Raises:
        HTTPException: 404 if project not found, 500 on failure.
    """
    try:
        query = select(Project).where(Project.id == project_id, Project.user_id == current_user.id)
        result = await session.execute(query)
        if not result.scalar_one_or_none():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
        
        query = select(Policy).where(Policy.project_id == project_id)
        result = await session.execute(query)
        policy = result.scalar_one_or_none()
        
        if not policy:
            policy = Policy(project_id=project_id, selection_json=policy_data.model_dump())
            session.add(policy)
        else:
            policy.selection_json = policy_data.model_dump()
            policy.updated_at = datetime.now(timezone.utc)
        
        await session.commit()
        await session.refresh(policy)
        return policy
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error updating policy: {str(e)}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to update policy.")

@project_router.get(
    "/{project_id}/audit-logs",
    response_model=List[AuditEventRead],
    summary="Get project audit logs",
    description="Returns all security audit events and usage metrics for a specific project.",
    responses={
        status.HTTP_401_UNAUTHORIZED: {"description": "Invalid Token or Token Expired"},
        status.HTTP_404_NOT_FOUND: {"description": "Project not found"}
    }
)
async def get_audit_logs(
    project_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    current_user: UserRead = Depends(get_current_user)
):
    """
    Retrieves all security audit events and usage metrics for a specific project.

    Args:
        project_id (uuid.UUID): ID of the project.
        session (AsyncSession): The database session.
        current_user (UserRead): The authenticated user making the request.

    Returns:
        List[AuditEventRead]: A chronological list of audit events (newest first).

    Raises:
        HTTPException: 404 if project not found, 500 on failure.
    """
    try:
        # Verify project ownership
        query = select(Project).where(Project.id == project_id, Project.user_id == current_user.id)
        result = await session.execute(query)
        if not result.scalar_one_or_none():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
            
        # Fetch audit events
        query = select(AuditEvent).where(AuditEvent.project_id == project_id).order_by(AuditEvent.created_at.desc())
        result = await session.execute(query)
        events = result.scalars().all()
        
        return events
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error fetching audit logs: {str(e)}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to fetch audit logs.")

@project_router.delete(
    "/{project_id}/audit-logs/{log_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete an audit log entry",
    description="Permanently removes a single audit event from a project. This action is immediate and cannot be undone.",
    responses={
        status.HTTP_401_UNAUTHORIZED: {"description": "Invalid Token or Token Expired"},
        status.HTTP_404_NOT_FOUND: {"description": "Audit log not found or unauthorized"}
    }
)
async def delete_audit_log(
    project_id: uuid.UUID,
    log_id: uuid.UUID,
    current_user: UserRead = Depends(get_current_user),
    session: AsyncSession = Depends(get_session)
):
    """
    Permanently deletes a specific audit log entry from a project.

    Args:
        project_id (uuid.UUID): ID of the parent project (used to verify ownership).
        log_id (uuid.UUID): ID of the audit event to delete.
        current_user (UserRead): The authenticated user making the request.
        session (AsyncSession): The database session.

    Returns:
        None: Returns 204 No Content on success.

    Raises:
        HTTPException: 404 if the project or audit log is not found or user is unauthorized.
    """
    try:
        # Verify project ownership
        query = select(Project).where(Project.id == project_id, Project.user_id == current_user.id)
        result = await session.execute(query)
        if not result.scalar_one_or_none():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

        # Find and delete the audit event
        query = select(AuditEvent).where(AuditEvent.id == log_id, AuditEvent.project_id == project_id)
        result = await session.execute(query)
        event = result.scalar_one_or_none()
        if not event:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit log not found")

        await session.delete(event)
        await session.commit()
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error deleting audit log: {str(e)}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to delete audit log.")

@project_router.delete(
    "/api-keys/{key_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete an API Key",
    description="Deactivates and removes an API key. This action is immediate and cannot be undone.",
    responses={
        status.HTTP_401_UNAUTHORIZED: {"description": "Invalid Token or Token Expired"},
        status.HTTP_404_NOT_FOUND: {"description": "API Key not found or unauthorized"}
    }
)
async def delete_api_key(
    key_id: uuid.UUID,
    current_user: UserRead = Depends(get_current_user),
    session: AsyncSession = Depends(get_session)
):
    """
    Deactivates and removes a specific API key.

    Args:
        key_id (uuid.UUID): The unique identifier of the API key to delete.
        current_user (UserRead): The authenticated user performing the deletion.
        session (AsyncSession): The database session.

    Raises:
        HTTPException: 404 if the key is not found or doesn't belong to the user.
        HTTPException: 500 if a database error occurs.
    """
    try:
        # Verify the key belongs to a project owned by the user
        query = select(APIKey).join(Project, APIKey.project_id == Project.id).where(
            APIKey.id == key_id,
            Project.user_id == current_user.id
        )
        result = await session.execute(query)
        api_key = result.scalar_one_or_none()
        
        if not api_key:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API Key not found or unauthorized")
        
        await session.delete(api_key)
        await session.commit()
        return None
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error deleting API Key: {str(e)}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to delete API key.")

@project_router.delete(
    "/{project_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a project",
    description="Deletes a project and all its associated data (API keys, policies, and audit logs). This action is permanent.",
    responses={
        status.HTTP_401_UNAUTHORIZED: {"description": "Invalid Token or Token Expired"},
        status.HTTP_404_NOT_FOUND: {"description": "Project not found or unauthorized"}
    }
)
async def delete_project(
    project_id: uuid.UUID,
    current_user: UserRead = Depends(get_current_user),
    session: AsyncSession = Depends(get_session)
):
    """
    Permanently deletes a project and performs a cascaded cleanup of all related records.

    This includes:
    - Audit logs and usage metrics.
    - All API keys associated with the project.
    - The project's security policy configuration.

    Args:
        project_id (uuid.UUID): The unique identifier of the project to delete.
        current_user (UserRead): The authenticated owner of the project.
        session (AsyncSession): The database session.

    Raises:
        HTTPException: 404 if the project is not found or unauthorized.
        HTTPException: 500 if any part of the cascaded cleanup fails.
    """
    try:
        # 1. Verify project ownership
        query = select(Project).where(Project.id == project_id, Project.user_id == current_user.id)
        result = await session.execute(query)
        project = result.scalar_one_or_none()
        
        if not project:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found or unauthorized")
        
        # 2. Perform Cascaded Cleanup
        # Delete Audit Events
        await session.execute(delete(AuditEvent).where(AuditEvent.project_id == project_id))
        
        # Delete API Keys
        await session.execute(delete(APIKey).where(APIKey.project_id == project_id))
        
        # Delete Policies
        await session.execute(delete(Policy).where(Policy.project_id == project_id))
        
        # 3. Delete the Project itself
        await session.delete(project)
        
        await session.commit()
        return None
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error deleting Project: {str(e)}", exc_info=True)
        await session.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to delete project and associated data.")

@project_router.post(
    "/{project_id}/generate-report",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Generate project-wide security report",
    description="Analyzes all logs for this project using an AI provider and emails a comprehensive report to the user.",
    responses={
        status.HTTP_401_UNAUTHORIZED: {"description": "Invalid Token or Token Expired"},
        status.HTTP_404_NOT_FOUND: {"description": "Project or Key not found"},
        status.HTTP_400_BAD_REQUEST: {"description": "No alert email configured"}
    }
)
async def generate_project_report(
    project_id: uuid.UUID,
    report_data: ReportRequest,
    background_tasks: BackgroundTasks,
    current_user: UserRead = Depends(get_current_user),
    session: AsyncSession = Depends(get_session)
):
    """
    Triggers an AI-powered security audit for the entire project.
    Uses the provider configuration of a selected API key to generate the report.

    Args:
        project_id (uuid.UUID): ID of the project to audit.
        report_data (ReportRequest): Contains the selected API Key ID for the provider.
        background_tasks (BackgroundTasks): FastAPI background task manager.
        current_user (UserRead): The authenticated user.
        session (AsyncSession): The database session.

    Returns:
        dict: A confirmation message that the task has started.

    Raises:
        HTTPException: 404 if project/key not found, 400 if email missing.
    """
    # 1. Verify project ownership
    query = select(Project).where(Project.id == project_id, Project.user_id == current_user.id)
    result = await session.execute(query)
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
    
    if not project.alert_email:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No alert email configured for this project.")

    # 2. Verify selected API Key belongs to the project
    query = select(APIKey).where(APIKey.id == report_data.api_key_id, APIKey.project_id == project_id)
    result = await session.execute(query)
    api_key = result.scalar_one_or_none()
    if not api_key:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Selected API Key not found for this project.")

    # 3. Trigger background task using the API Key's provider details
    # 3. Generate report synchronously
    html_body = await generate_comprehensive_report(
        target_id=str(project_id),
        target_type="project",
        provider_url=api_key.backend_url,
        provider_key=api_key.backend_api_key or "",
        user_email=project.alert_email,
        model=report_data.model,
    )
    return {"report_html": html_body, "message": "Report generated successfully."}

@project_router.post(
    "/api-keys/{api_key_id}/generate-report",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Generate API Key specific report",
    description="Analyzes logs for a specific API Key using its configured provider and emails a report to the user.",
    responses={
        status.HTTP_401_UNAUTHORIZED: {"description": "Invalid Token or Token Expired"},
        status.HTTP_404_NOT_FOUND: {"description": "API Key not found"},
        status.HTTP_400_BAD_REQUEST: {"description": "No alert email configured"}
    }
)
async def generate_apikey_report(
    api_key_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    model: str,
    current_user: UserRead = Depends(get_current_user),
    session: AsyncSession = Depends(get_session)
):
    """
    Triggers an AI-powered security audit for a specific API key using its own provider settings.

    Args:
        api_key_id (uuid.UUID): ID of the API key to audit.
        background_tasks (BackgroundTasks): FastAPI background task manager.
        current_user (UserRead): The authenticated user.
        session (AsyncSession): The database session.

    Returns:
        dict: A confirmation message that the task has started.

    Raises:
        HTTPException: 404 if API Key not found, 400 if parent project email missing.
    """
    # 1. Verify key belongs to user
    query = select(APIKey).join(Project, APIKey.project_id == Project.id).where(
        APIKey.id == api_key_id,
        Project.user_id == current_user.id
    )
    result = await session.execute(query)
    api_key = result.scalar_one_or_none()
    if not api_key:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API Key not found")
    
    # 2. Get project email
    query = select(Project.alert_email).where(Project.id == api_key.project_id)
    result = await session.execute(query)
    email = result.scalar()
    
    if not email:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No alert email configured for the parent project.")

    # 3. Generate report synchronously
    html_body = await generate_comprehensive_report(
        target_id=str(api_key_id),
        target_type="apikey",
        provider_url=api_key.backend_url,
        provider_key=api_key.backend_api_key or "",
        user_email=email,
        model=model
    )
    return {"report_html": html_body, "message": "Report generated successfully."}
