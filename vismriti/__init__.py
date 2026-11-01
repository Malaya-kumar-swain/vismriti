"""Vismriti: DPDP-ready consent, purpose limitation and right-to-erasure for RAG and AI agents."""

from .consent import ConsentLedger, Purpose
from .core import Vismriti
from .erasure import DeletionCertificate, ErasureCoordinator
from .evidence import EvidenceLog
from .pii import Finding, IndianPIIDetector, mask, verhoeff_valid
from .retrieval import PurposeBoundRetriever
from .stores import AgentMemory, Chunk, ErasableStore, InMemoryVectorStore, LogStore, ResponseCache

__version__ = "0.1.0"

__all__ = [
    "AgentMemory", "Chunk", "ConsentLedger", "DeletionCertificate", "ErasableStore",
    "ErasureCoordinator", "EvidenceLog", "Finding", "InMemoryVectorStore", "IndianPIIDetector",
    "LogStore", "Purpose", "PurposeBoundRetriever", "ResponseCache", "Vismriti", "mask",
    "verhoeff_valid", "__version__",
]
