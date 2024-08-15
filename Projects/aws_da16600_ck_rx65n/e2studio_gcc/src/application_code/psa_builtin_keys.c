#include "psa_builtin_keys.h"

psa_status_t mbedtls_psa_platform_get_builtin_key(
     mbedtls_svc_key_id_t key_id,
     psa_key_lifetime_t *lifetime,
     psa_drv_slot_number_t *slot_number)
{
	switch (key_id) {
	default:
		return PSA_ERROR_DOES_NOT_EXIST;
	}
}
