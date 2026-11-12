from flask import request

from models import Project, db


def update_settings(project_id):
    # ❌ FLAW: fetched by raw id only — no scoping to the authenticated tenant
    project = db.session.get(Project, project_id)
    project.name = request.json.get("name")
    db.session.commit()
    return project
