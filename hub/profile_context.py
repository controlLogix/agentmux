"""Explicit profile display values and the private registered selection binding."""
from dataclasses import dataclass
import hashlib
import re
import unicodedata


@dataclass(frozen=True, slots=True, repr=False, kw_only=True)
class ProfileContext:
    """Display values only. Project does not grant authorization scope."""
    environment: str | None = None
    project: str | None = None

    def __post_init__(self):
        if self.environment is None and self.project is None:
            raise ValueError("profile context needs a supplied value")
        for value in (self.environment, self.project):
            if value is None:
                continue
            if (type(value) is not str or not value or value.strip() != value
                    or any(unicodedata.category(char) == "Cc" or char in "\u2028\u2029" for char in value)):
                raise ValueError("invalid profile display value")
            try:
                encoded = value.encode("utf-8")
            except UnicodeEncodeError:
                raise ValueError("invalid profile display value") from None
            if len(encoded) > 128:
                raise ValueError("invalid profile display value")

    def __repr__(self):
        return "<ProfileContext private>"

    def as_dict(self):
        return {key: value for key, value in (("environment", self.environment), ("project", self.project))
                if value is not None}


@dataclass(frozen=True, slots=True, repr=False, kw_only=True)
class RegisteredProfileContext:
    """Private pins checked against the same selection bytes used for startup.

    Only the installed bootstrap supplies this record after registration admission.
    It is not an authorization credential and must not travel with agents.
    """
    selection_sha256: str
    profile_id: str
    instance_id: str
    context: ProfileContext

    def __post_init__(self):
        if (type(self.context) is not ProfileContext
                or type(self.selection_sha256) is not str
                or re.fullmatch(r"sha256:[0-9a-f]{64}", self.selection_sha256) is None
                or type(self.profile_id) is not str or re.fullmatch(r"profile_[0-9a-f]{32}", self.profile_id) is None
                or type(self.instance_id) is not str or re.fullmatch(r"instance_[0-9a-f]{32}", self.instance_id) is None):
            raise ValueError("invalid registered profile binding")

    def __repr__(self):
        return "<RegisteredProfileContext private>"

    def matches_selection(self, raw: bytes, *, profile_id: str, instance_id: str) -> bool:
        """Compare admitted pins inside the existing selection reader."""
        return (type(raw) is bytes and self.profile_id == profile_id and self.instance_id == instance_id
                and self.selection_sha256 == "sha256:" + hashlib.sha256(raw).hexdigest())
