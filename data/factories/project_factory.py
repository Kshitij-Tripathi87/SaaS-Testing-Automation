import uuid
from datetime import datetime
from typing import Dict, Optional


class ProjectFactory:
    @staticmethod
    def generate(
        tenant_id: str,
        name: Optional[str] = None,
        team_members: Optional[list] = None,
    ) -> Dict:
        unique_id = uuid.uuid4().hex[:8]
        return {
            "name": name or f"Test Project {unique_id}",
            "description": (
                f"Automated test project created {datetime.utcnow().isoformat()}"
            ),
            "team_members": team_members or [
                {
                    "email": f"testuser_{unique_id}@{tenant_id}.com",
                    "role": "admin",
                }
            ],
            "metadata": {
                "test_run_id": unique_id,
                "test_timestamp": datetime.utcnow().isoformat(),
                "tenant_id": tenant_id,
            },
        }

    @staticmethod
    def generate_unique_name(prefix="Test Project") -> str:
        return f"{prefix} {uuid.uuid4().hex[:8]}"
