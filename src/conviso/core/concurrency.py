"""
Concurrency helpers
-------------------
Shared primitives for parallel execution across commands.
"""

from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Iterable, TypeVar, List, Optional

T = TypeVar("T")
R = TypeVar("R")
DEFAULT_WORKERS = 8


def set_default_workers(workers: int):
    global DEFAULT_WORKERS
    DEFAULT_WORKERS = workers if workers and workers > 0 else 1


def get_default_workers() -> int:
    return DEFAULT_WORKERS


def resolve_workers(workers: Optional[int]) -> int:
    if workers is None:
        return get_default_workers()
    return workers if workers > 0 else 1


def parallel_map(func: Callable[[T], R], items: Iterable[T], workers: Optional[int] = None) -> List[R]:
    """
    Apply func to items in parallel (I/O bound), preserving order.
    Falls back to sequential execution when workers <= 1.
    """
    data = list(items)
    if not data:
        return []
    max_workers = resolve_workers(workers)
    if max_workers <= 1:
        return [func(item) for item in data]
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        return list(pool.map(func, data))
