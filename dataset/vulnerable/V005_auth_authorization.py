def get_admin_report(user):
    return {
        "user": user["username"],
        "report": "confidential-admin-report"
    }