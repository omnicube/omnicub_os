
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <rte_config.h>
#include <rte_eal.h>
#include <rte_debug.h>
#include <rte_mempool.h>
#include <rte_malloc.h>

#include "omnios/vtophys.h"

static const char *ealargs[] = {
	"vtophys",
	"-c 0x1",
	"-n 4",
};

static int
vtophys_negative_test(void)
{
	void *p = NULL;
	int i;
	unsigned int size = 1;
	int rc = 0;

	for (i = 0; i < 31; i++) {
		p = malloc(size);
		if (p == NULL)
			continue;

		if (vtophys(p) != VTOPHYS_ERROR) {
			rc = -1;
			printf("Err: VA=%p is mapped to a huge_page,\n", p);
			free(p);
			break;
		}

		free(p);
		size = size << 1;
	}

	if (!rc)
		printf("vtophys_negative_test passed\n");
	else
		printf("vtophys_negative_test failed\n");

	return rc;
}

static int
vtophys_positive_test(void)
{
	void *p = NULL;
	int i;
	unsigned int size = 1;
	int rc = 0;

	for (i = 0; i < 31; i++) {
		p = rte_malloc("vtophys_test", size, 512);
		if (p == NULL)
			continue;

		if (vtophys(p) == VTOPHYS_ERROR) {
			rc = -1;
			printf("Err: VA=%p is not mapped to a huge_page,\n", p);
			rte_free(p);
			break;
		}

		rte_free(p);
		size = size << 1;
	}

	if (!rc)
		printf("vtophys_positive_test passed\n");
	else
		printf("vtophys_positive_test failed\n");

	return rc;
}


int
main(int argc, char **argv)
{
	int rc;

	rc = rte_eal_init(sizeof(ealargs) / sizeof(ealargs[0]),
			  (char **)(void *)(uintptr_t)ealargs);

	if (rc < 0) {
		fprintf(stderr, "Could not init eal\n");
		exit(1);
	}

	rc = vtophys_negative_test();
	if (rc < 0)
		return rc;

	rc = vtophys_positive_test();
	return rc;
}
