#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

/* Minimal stubs for SGT testing */
#define INFO(fmt, ...) printf(fmt "\n", ##__VA_ARGS__)
#define PVAL_OK 0
#define PVAL_ESGT_COVERAGE -201
#define PVAL_ESGT_CONFLICT -202
#define PVAL_ESGT_RD_ILLEGAL -203

#define GRANULE_SIZE (1 << 12)  /* 4KB */
#define SGT_MAX_ENTRIES 256
#define PARSER_MAX_MAPS 4

/* SGT structures */
struct sgt_entry {
	uint64_t gpa;
	unsigned long pa;
	unsigned long rd;
};

struct sgt {
	size_t count;
	struct sgt_entry entries[SGT_MAX_ENTRIES];
};

/* Helper: add entry to SGT */
static void sgt_add_entry(struct sgt *sgt, uint64_t gpa, unsigned long pa, unsigned long rd)
{
	if (sgt->count < SGT_MAX_ENTRIES) {
		sgt->entries[sgt->count].gpa = gpa;
		sgt->entries[sgt->count].pa = pa;
		sgt->entries[sgt->count].rd = rd;
		sgt->count++;
	}
}

/* Helper: check if value in set */
static bool set_contains_ulong(const unsigned long *set, size_t n, unsigned long v)
{
	for (size_t i = 0; i < n; i++)
		if (set[i] == v) return true;
	return false;
}

static bool set_contains_u64(const uint64_t *set, size_t n, uint64_t v)
{
	for (size_t i = 0; i < n; i++)
		if (set[i] == v) return true;
	return false;
}

static int set_add_ulong_strict(unsigned long *set, size_t *n, size_t cap, unsigned long v)
{
	if (set_contains_ulong(set, *n, v))
		return 0;
	if (*n >= cap)
		return -1;
	set[(*n)++] = v;
	return 0;
}

/* Phase A: Check coverage and PA consistency */
static int validate_memobj_pa_set(const struct sgt *sgt,
                                  uint64_t size,
                                  const unsigned long *explicit_rds,
                                  const uint64_t *explicit_bases,
                                  size_t n_explicit,
                                  unsigned long *pa_set,
                                  size_t *n_pa_set,
                                  size_t pa_cap)
{
	const uint64_t step = (uint64_t)GRANULE_SIZE;
	const uint64_t n_pages = size / step;

	static unsigned long canonical_pa[SGT_MAX_ENTRIES];
	static bool canonical_set[SGT_MAX_ENTRIES];

	for (uint64_t k = 0; k < n_pages; k++) {
		canonical_set[k] = false;
		canonical_pa[k] = 0;
	}

	*n_pa_set = 0;

	/* For each explicit RD and its base GPA, check coverage and consistency */
	for (size_t e = 0; e < n_explicit; e++) {
		const unsigned long rd = explicit_rds[e];
		const uint64_t base = explicit_bases[e];

		for (uint64_t k = 0; k < n_pages; k++) {
			const uint64_t gpa = base + k * step;
			unsigned long pa = 0;
			bool found = false;

			/* Find PA for this (rd, gpa) in SGT */
			for (size_t i = 0; i < sgt->count; i++) {
				if ((uint64_t)sgt->entries[i].gpa == gpa && sgt->entries[i].rd == rd) {
					pa = sgt->entries[i].pa;
					found = true;
					break;
				}
			}

			if (!found) {
				INFO("  Coverage miss: rd=0x%lx gpa=0x%llx", rd, (unsigned long long)gpa);
				return PVAL_ESGT_COVERAGE;
			}

			/* Check PA consistency across explicit RDs for same page index */
			if (!canonical_set[k]) {
				canonical_set[k] = true;
				canonical_pa[k] = pa;
			} else if (canonical_pa[k] != pa) {
				INFO("  PA conflict: page_idx=%llu pa_a=0x%lx pa_b=0x%lx",
				     (unsigned long long)k, canonical_pa[k], pa);
				return PVAL_ESGT_CONFLICT;
			}

			/* Add to PA set */
			if (set_add_ulong_strict(pa_set, n_pa_set, pa_cap, pa) != 0) {
				INFO("  PA set overflow");
				return PVAL_ESGT_COVERAGE;
			}
		}
	}

	return PVAL_OK;
}

/* Phase B: Check PA exclusivity (no extra RDs without ANY) */
static int enforce_memobj_pa_exclusivity(const struct sgt *sgt,
                                         const unsigned long *pa_set,
                                         size_t n_pa_set,
                                         const unsigned long *explicit_rds,
                                         size_t n_explicit,
                                         bool has_any)
{
	unsigned long extra_rds[64];
	size_t n_extra_rds = 0;

	for (size_t i = 0; i < sgt->count; i++) {
		const struct sgt_entry *e = &sgt->entries[i];
		const unsigned long pa = e->pa;

		/* Only check PAs that belong to this object */
		if (!set_contains_ulong(pa_set, n_pa_set, pa))
			continue;

		const unsigned long rd = e->rd;

		/* Is this RD in the explicit list? */
		if (set_contains_ulong(explicit_rds, n_explicit, rd))
			continue;  /* Allowed */

		/* Extra RD (not explicit) - only allowed if has_any */
		if (!has_any) {
			INFO("  Illegal extra rd=0x%lx (no ANY)", rd);
			return PVAL_ESGT_RD_ILLEGAL;
		}

		/* Track distinct extra RDs */
		if (!set_contains_ulong(extra_rds, n_extra_rds, rd)) {
			if (n_extra_rds < (sizeof(extra_rds)/sizeof(extra_rds[0]))) {
				extra_rds[n_extra_rds++] = rd;
			}
		}
	}

	return PVAL_OK;
}

/* Test 1: Valid SGT with full coverage */
static void test_sgt_valid_coverage(void)
{
	printf("\n=== Test 1: Valid SGT with full coverage ===\n");

	struct sgt sgt = {0};
	uint64_t size = 4 * GRANULE_SIZE;  /* 4 pages */
	
	/* Explicit RDs and their base GPAs */
	unsigned long explicit_rds[1] = {0x1000};
	uint64_t explicit_bases[1] = {0x10000};
	size_t n_explicit = 1;

	/* Add entries for all pages for RD 0x1000 */
	for (int i = 0; i < 4; i++) {
		sgt_add_entry(&sgt, 0x10000 + i * GRANULE_SIZE, 0x20000 + i * GRANULE_SIZE, 0x1000);
	}

	unsigned long pa_set[256];
	size_t n_pa_set = 0;

	int rc = validate_memobj_pa_set(&sgt, size, explicit_rds, explicit_bases, n_explicit,
	                                 pa_set, &n_pa_set, 256);
	assert(rc == PVAL_OK);
	assert(n_pa_set == 4);
	printf("PASS: Full coverage validated (4 pages)\n");
}

/* Test 2: Missing coverage (page not in SGT) */
static void test_sgt_missing_coverage(void)
{
	printf("\n=== Test 2: Missing coverage ===\n");

	struct sgt sgt = {0};
	uint64_t size = 4 * GRANULE_SIZE;

	unsigned long explicit_rds[1] = {0x1000};
	uint64_t explicit_bases[1] = {0x10000};
	size_t n_explicit = 1;

	/* Add only 3 of 4 pages (missing page 2) */
	sgt_add_entry(&sgt, 0x10000, 0x20000, 0x1000);
	sgt_add_entry(&sgt, 0x11000, 0x21000, 0x1000);
	/* Skip page 2 at 0x12000 */
	sgt_add_entry(&sgt, 0x13000, 0x23000, 0x1000);

	unsigned long pa_set[256];
	size_t n_pa_set = 0;

	int rc = validate_memobj_pa_set(&sgt, size, explicit_rds, explicit_bases, n_explicit,
	                                 pa_set, &n_pa_set, 256);
	assert(rc == PVAL_ESGT_COVERAGE);
	printf("PASS: Missing coverage detected\n");
}

/* Test 3: PA consistency across two explicit RDs */
static void test_sgt_pa_consistency(void)
{
	printf("\n=== Test 3: PA consistency across explicit RDs ===\n");

	struct sgt sgt = {0};
	uint64_t size = 2 * GRANULE_SIZE;  /* 2 pages */

	unsigned long explicit_rds[2] = {0x1000, 0x2000};
	uint64_t explicit_bases[2] = {0x10000, 0x30000};
	size_t n_explicit = 2;

	/* Both RDs should have same PA for same page index */
	/* Page 0: both RDs -> same PA (0x50000) */
	sgt_add_entry(&sgt, 0x10000, 0x50000, 0x1000);
	sgt_add_entry(&sgt, 0x30000, 0x50000, 0x2000);

	/* Page 1: both RDs -> same PA (0x51000) */
	sgt_add_entry(&sgt, 0x11000, 0x51000, 0x1000);
	sgt_add_entry(&sgt, 0x31000, 0x51000, 0x2000);

	unsigned long pa_set[256];
	size_t n_pa_set = 0;

	int rc = validate_memobj_pa_set(&sgt, size, explicit_rds, explicit_bases, n_explicit,
	                                 pa_set, &n_pa_set, 256);
	assert(rc == PVAL_OK);
	assert(n_pa_set == 2);  /* Only 2 unique PAs */
	printf("PASS: PA consistency verified (2 RDs, shared PAs)\n");
}

/* Test 4: PA conflict across RDs (different PAs for same page) */
static void test_sgt_pa_conflict(void)
{
	printf("\n=== Test 4: PA conflict across RDs ===\n");

	struct sgt sgt = {0};
	uint64_t size = 2 * GRANULE_SIZE;

	unsigned long explicit_rds[2] = {0x1000, 0x2000};
	uint64_t explicit_bases[2] = {0x10000, 0x30000};
	size_t n_explicit = 2;

	/* Page 0: RD 0x1000 -> PA 0x50000, RD 0x2000 -> PA 0x60000 (CONFLICT!) */
	sgt_add_entry(&sgt, 0x10000, 0x50000, 0x1000);
	sgt_add_entry(&sgt, 0x30000, 0x60000, 0x2000);  /* Different PA! */

	sgt_add_entry(&sgt, 0x11000, 0x51000, 0x1000);
	sgt_add_entry(&sgt, 0x31000, 0x61000, 0x2000);

	unsigned long pa_set[256];
	size_t n_pa_set = 0;

	int rc = validate_memobj_pa_set(&sgt, size, explicit_rds, explicit_bases, n_explicit,
	                                 pa_set, &n_pa_set, 256);
	assert(rc == PVAL_ESGT_CONFLICT);
	printf("PASS: PA conflict detected\n");
}

/* Test 5: Illegal extra RD (no ANY permission) */
static void test_sgt_illegal_extra_rd(void)
{
	printf("\n=== Test 5: Illegal extra RD without ANY ===\n");

	struct sgt sgt = {0};
	uint64_t size = 2 * GRANULE_SIZE;

	unsigned long explicit_rds[1] = {0x1000};
	uint64_t explicit_bases[1] = {0x10000};
	size_t n_explicit = 1;

	/* Add pages for RD 0x1000 (explicit) */
	sgt_add_entry(&sgt, 0x10000, 0x50000, 0x1000);
	sgt_add_entry(&sgt, 0x11000, 0x51000, 0x1000);

	/* Add same PAs but via extra RD 0x2000 (not explicit, no ANY) */
	sgt_add_entry(&sgt, 0x20000, 0x50000, 0x2000);  /* Extra RD maps same PA */
	sgt_add_entry(&sgt, 0x21000, 0x51000, 0x2000);

	unsigned long pa_set[256];
	size_t n_pa_set = 0;

	int rc = validate_memobj_pa_set(&sgt, size, explicit_rds, explicit_bases, n_explicit,
	                                 pa_set, &n_pa_set, 256);
	assert(rc == PVAL_OK);  /* Coverage OK */

	/* Now check exclusivity without ANY */
	rc = enforce_memobj_pa_exclusivity(&sgt, pa_set, n_pa_set, explicit_rds, n_explicit, false);
	assert(rc == PVAL_ESGT_RD_ILLEGAL);
	printf("PASS: Illegal extra RD detected (no ANY)\n");
}

/* Test 6: Allowed extra RD with ANY permission */
static void test_sgt_allowed_extra_rd_with_any(void)
{
	printf("\n=== Test 6: Allowed extra RD with ANY ===\n");

	struct sgt sgt = {0};
	uint64_t size = 2 * GRANULE_SIZE;

	unsigned long explicit_rds[1] = {0x1000};
	uint64_t explicit_bases[1] = {0x10000};
	size_t n_explicit = 1;

	/* Add pages for RD 0x1000 (explicit) */
	sgt_add_entry(&sgt, 0x10000, 0x50000, 0x1000);
	sgt_add_entry(&sgt, 0x11000, 0x51000, 0x1000);

	/* Add same PAs via extra RD 0x2000, but this time we allow it with ANY */
	sgt_add_entry(&sgt, 0x20000, 0x50000, 0x2000);
	sgt_add_entry(&sgt, 0x21000, 0x51000, 0x2000);

	unsigned long pa_set[256];
	size_t n_pa_set = 0;

	int rc = validate_memobj_pa_set(&sgt, size, explicit_rds, explicit_bases, n_explicit,
	                                 pa_set, &n_pa_set, 256);
	assert(rc == PVAL_OK);

	/* Now check exclusivity WITH ANY enabled */
	rc = enforce_memobj_pa_exclusivity(&sgt, pa_set, n_pa_set, explicit_rds, n_explicit, true);
	assert(rc == PVAL_OK);
	printf("PASS: Extra RD allowed with ANY\n");
}

/* Test 7: Multiple explicit RDs with shared PA (both RDs cover all pages) */
static void test_sgt_multiple_explicit_rds(void)
{
	printf("\n=== Test 7: Multiple explicit RDs (both cover all pages) ===\n");

	struct sgt sgt = {0};
	uint64_t size = 2 * GRANULE_SIZE;  /* 2 pages total */

	/* RD 0x1000 at base 0x10000, RD 0x2000 at base 0x30000 - both map the same 2-page object */
	unsigned long explicit_rds[2] = {0x1000, 0x2000};
	uint64_t explicit_bases[2] = {0x10000, 0x30000};
	size_t n_explicit = 2;

	/* RD 0x1000: maps both pages to PAs 0x50000, 0x51000 */
	sgt_add_entry(&sgt, 0x10000, 0x50000, 0x1000);
	sgt_add_entry(&sgt, 0x11000, 0x51000, 0x1000);

	/* RD 0x2000: must map to SAME PAs for same page indices (0x50000, 0x51000) */
	sgt_add_entry(&sgt, 0x30000, 0x50000, 0x2000);
	sgt_add_entry(&sgt, 0x31000, 0x51000, 0x2000);

	unsigned long pa_set[256];
	size_t n_pa_set = 0;

	int rc = validate_memobj_pa_set(&sgt, size, explicit_rds, explicit_bases, n_explicit,
	                                 pa_set, &n_pa_set, 256);
	assert(rc == PVAL_OK);
	assert(n_pa_set == 2);  /* 2 unique PAs shared across both RDs */
	printf("PASS: Multiple explicit RDs with shared PAs validated\n");
}

int main(void)
{
	printf("Running SGT validation tests...\n");

	test_sgt_valid_coverage();
	test_sgt_missing_coverage();
	test_sgt_pa_consistency();
	test_sgt_pa_conflict();
	test_sgt_illegal_extra_rd();
	test_sgt_allowed_extra_rd_with_any();
	test_sgt_multiple_explicit_rds();

	printf("\n=== All SGT tests passed! ===\n");
	return 0;
}
