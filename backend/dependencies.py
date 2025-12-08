from typing import TYPE_CHECKING
from fastapi import Depends, HTTPException, status

from backend.auth import get_current_user_required

if TYPE_CHECKING:
    from database.models import User


def require_admin(user: "User" = Depends(get_current_user_required)):
    if getattr(user, "role", None) != "ADMIN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Требуются права администратора",
        )
    return user