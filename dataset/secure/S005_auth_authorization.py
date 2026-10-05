def get_admin_report(user):
    if user.get("role") != "admin":
        raise PermissionError("Administrator access required")

    return {
        "user": user["username"],
        "report": "confidential-admin-report"
    }