"""Bounded operator-safe UI error descriptions."""


def describe_error(error: Exception, *, include_detail: bool = False) -> dict[str, str]:
    code = str(getattr(error, "code", "ui_refresh_failed"))
    message = str(error)[:240] or type(error).__name__
    value = {"code": code, "message": message}
    if include_detail:
        value["detail"] = type(error).__name__
    return value
