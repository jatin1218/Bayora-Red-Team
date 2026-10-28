from datetime import datetime, timezone, timedelta
from typing import Literal
from uuid import uuid4
from pydantic import BaseModel, ConfigDict, Field, model_validator, field_validator

CATEGORIES = ('prompt_injection', 'sensitive_data', 'system_exposure', 'rag_manipulation', 'tool_misuse')
Category = Literal['prompt_injection', 'sensitive_data', 'system_exposure', 'rag_manipulation', 'tool_misuse']

class Contract(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True, strict=True)
    schema_version: Literal['1.0'] = '1.0'
    contract_id: str = Field(default_factory=lambda: str(uuid4()), pattern=r'^[a-zA-Z0-9_-]{1,80}$')
    project_id: str = Field(default='demo', pattern=r'^[a-zA-Z0-9_-]{1,80}$')
    target: Literal['demo://safe', 'demo://vulnerable', 'demo://ambiguous'] = 'demo://safe'
    authorization: Literal['bundled-synthetic-target-only'] = 'bundled-synthetic-target-only'
    expires_at: str = Field(default_factory=lambda: (datetime.now(timezone.utc)+timedelta(days=1)).isoformat())
    categories: tuple[Category, ...] = CATEGORIES
    catalog_version: Literal['1.0'] = '1.0'
    trials: int = Field(default=3, ge=1, le=4)
    max_attempts: int = Field(default=20, ge=1, le=20)
    wall_seconds: int = Field(default=30, ge=1, le=600)
    per_attempt_input_bytes: int = Field(default=4096, ge=128, le=65536)
    per_attempt_output_bytes: int = Field(default=4096, ge=32, le=65536)
    max_total_bytes: int = Field(default=100000, ge=100, le=1000000)
    max_cost_usd: Literal[0] = 0
    concurrency: Literal[1] = 1
    raw_artifacts: Literal[False] = False
    retention_days: int = Field(default=7, ge=1, le=30)
    replay_min_trials: int = Field(default=3, ge=2, le=4)
    replay_max_bypasses: Literal[0] = 0
    required_checks: tuple[str, ...] = ('contract', 'budgets', 'detector_controls', 'evidence', 'cleanup', 'worker_isolation', 'egress')

    @field_validator('categories', 'required_checks', mode='before')
    @classmethod
    def arrays_to_tuples(cls, value):
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode='after')
    def validate_scope(self):
        expiration = datetime.fromisoformat(self.expires_at.replace('Z', '+00:00'))
        if expiration.tzinfo is None or expiration <= datetime.now(timezone.utc):
            raise ValueError('Contract expiry must be timezone-aware and in the future')
        if not self.categories or len(set(self.categories)) != len(self.categories):
            raise ValueError('Categories must be nonempty and unique')
        if len(self.categories) * self.trials > self.max_attempts:
            raise ValueError('Planned trials exceed max_attempts')
        expected = {'contract', 'budgets', 'detector_controls', 'evidence', 'cleanup', 'worker_isolation', 'egress'}
        if set(self.required_checks) != expected or len(self.required_checks) != len(expected):
            raise ValueError('Mandatory validity gates cannot be removed or duplicated')
        return self

    @classmethod
    def from_dict(cls, value):
        # JSON arrays are allowed, but Python constructor validation remains strict.
        import json
        return cls.model_validate_json(json.dumps(value))

    def as_dict(self):
        return self.model_dump(mode='json')
