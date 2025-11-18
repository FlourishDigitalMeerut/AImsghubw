<<<<<<< HEAD
from pydantic import BaseModel
from typing import List, Optional

class IdeaInput(BaseModel):
    ai_idea: str

class KnowledgeBaseInput(BaseModel):
    url: Optional[str] = None

class ChatTestInput(BaseModel):
    question: str

class CampaignCreate(BaseModel):
    name: str
    message: Optional[str]
    campaign_type: str
=======
from pydantic import BaseModel
from typing import List, Optional

class IdeaInput(BaseModel):
    ai_idea: str

class KnowledgeBaseInput(BaseModel):
    url: Optional[str] = None

class ChatTestInput(BaseModel):
    question: str

class CampaignCreate(BaseModel):
    name: str
    message: Optional[str]
    campaign_type: str
>>>>>>> 9c30675a2db80bc2621c532f163136b80a8c3e15
    contacts: Optional[List[str]]