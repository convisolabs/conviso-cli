"""
Vulnerabilities Timeline Schemas
--------------------------------
Friendly table/csv headers for vulnerability timeline outputs.
"""


class VulnerabilitiesTimelineSchema:
    def __init__(self):
        self.display_headers = {
            "projectId": "Project ID",
            "issueId": "Vulnerability ID",
            "issueTitle": "Vulnerability",
            "currentIssueStatus": "Current Status",
            "eventId": "Event ID",
            "createdAt": "Event At",
            "actorName": "Changed By",
            "actorEmail": "Changed By Email",
            "actionType": "Action",
            "fromStatus": "From Status",
            "toStatus": "To Status",
            "statusChange": "Status Change",
        }


class VulnerabilitiesTimelineLastSchema:
    def __init__(self):
        self.display_headers = {
            "projectId": "Project ID",
            "issueId": "Vulnerability ID",
            "issueTitle": "Vulnerability",
            "currentIssueStatus": "Current Status",
            "lastChangedAt": "Last Changed At",
            "lastChangedBy": "Last Changed By",
            "lastChangedByEmail": "Last Changed By Email",
            "fromStatus": "From Status",
            "toStatus": "To Status",
            "actionType": "Action",
        }


timeline_schema = VulnerabilitiesTimelineSchema()
timeline_last_schema = VulnerabilitiesTimelineLastSchema()
