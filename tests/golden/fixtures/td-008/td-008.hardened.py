from flask import g, request

from models import Project, db


def update_settings(project_id):
    # ✅ HARDENED: compound filter scopes the lookup to the authenticated tenant
    project = (
        db.session.query(Project)
        .filter(
            Project.id == project_id,
            Project.organization_id == g.user.organization_id,
        )
        .one()
    )
    project.name = request.json.get("name")
    db.session.commit()
    return project
