#ifndef PSA_BUILTIN_KEYS_H_
#define PSA_BUILTIN_KEYS_H_

#include <psa/crypto.h>

psa_status_t mbedtls_psa_platform_get_builtin_key(
     mbedtls_svc_key_id_t key_id,
     psa_key_lifetime_t *lifetime,
     psa_drv_slot_number_t *slot_number);

#endif /* PSA_BUILTIN_KEYS_H_ */
