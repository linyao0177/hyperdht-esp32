#ifndef POC_SODIUM_CHECK_H
#define POC_SODIUM_CHECK_H

// Checks every libsodium primitive HyperDHT relies on against vectors from
// the host libsodium, then benchmarks them. Returns the number of failures.
int
poc_sodium_run (void);

#endif
