"""
Project Requirements Activities Schema
--------------------------------------
Defines output columns for listing project requirements and related activities.
"""


class ProjectRequirementsActivitiesSchema:
    def __init__(self):
        self.display_headers = {
            "projectId": "Project ID",
            "projectLabel": "Project",
            "requirementId": "Requirement ID",
            "requirementLabel": "Requirement",
            "activityId": "Activity ID",
            "activityTitle": "Activity",
            "activityStatus": "Status",
            "checkType": "Type",
            "checkCategory": "Category",
            "checkLabel": "Check",
            "hasAttachments": "Has Attachments",
            "attachments": "Attachments",
            "historyEvents": "History Events",
            "historyEmails": "History Emails",
            "historyLastAt": "Last History At",
            "startedAt": "Started At",
            "finishedAt": "Finished At",
        }


schema = ProjectRequirementsActivitiesSchema()
