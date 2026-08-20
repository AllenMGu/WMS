"""Shared application errors for controlled GSP workflows."""


class WorkflowError(Exception):
    def __init__(self, status_code: int, message: str, findings: list[dict] | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.message = message
        self.findings = findings or []

    @property
    def detail(self):
        if self.findings:
            return {"message": self.message, "findings": self.findings}
        return self.message
