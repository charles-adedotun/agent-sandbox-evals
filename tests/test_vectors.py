"""Unit tests for adversarial attack matrix."""

from agent_sandbox_evals.models import AttackCategory
from agent_sandbox_evals.vectors.matrix import ATTACK_VECTORS, get_all_vectors, get_vectors_by_category


def test_vector_matrix_completeness():
    vectors = get_all_vectors()
    assert len(vectors) >= 15, f"Expected at least 15 attack vectors, found {len(vectors)}"

    # Ensure IDs are unique
    ids = [v.id for v in vectors]
    assert len(ids) == len(set(ids)), "Vector IDs must be strictly unique"

    # Ensure all 5 required attack categories are populated
    categories = {v.category for v in vectors}
    required = {
        AttackCategory.SSRF,
        AttackCategory.FILESYSTEM,
        AttackCategory.PRIVILEGE,
        AttackCategory.RESOURCE_DOS,
        AttackCategory.SECRET_LEAK,
    }
    assert required.issubset(categories), f"Missing categories: {required - categories}"


def test_filter_by_category():
    ssrf_vecs = get_vectors_by_category(AttackCategory.SSRF)
    assert len(ssrf_vecs) >= 4
    for v in ssrf_vecs:
        assert v.category == AttackCategory.SSRF
