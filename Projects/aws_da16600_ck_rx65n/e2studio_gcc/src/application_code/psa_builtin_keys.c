#include "psa_builtin_keys.h"

#include "psa_crypto_core.h"

static size_t g_key_buffer_size = 32;
static uint8_t g_key_buffer[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

psa_status_t mbedtls_psa_platform_get_builtin_key(
     mbedtls_svc_key_id_t key_id,
     psa_key_lifetime_t *lifetime,
     psa_drv_slot_number_t *slot_number)
{
	switch (key_id) {
	case PSA_KEY_ID_BUILTIN_IOTREFERENCE_RX_DEVICE_PRIVATE_KEY:
		*lifetime = PSA_KEY_LIFETIME_IOTREFERENCE_RX;
		*slot_number = PSA_DRV_SLOT_IOTREFERENCE_RX_DEVICE_PRIVATE_KEY;
		return PSA_SUCCESS;

	default:
		return PSA_ERROR_DOES_NOT_EXIST;
	}
}

psa_status_t psa_driver_iotreference_rx__get_key_buffer_size(
    const psa_key_attributes_t *attributes,
    size_t *key_buffer_size )
{
	*key_buffer_size = sizeof(psa_drv_slot_number_t);
	return PSA_SUCCESS;
}

psa_status_t psa_driver_iotreference_rx_get_builtin_key(
    psa_drv_slot_number_t slot_number,
    psa_key_attributes_t *attributes,
    uint8_t *key_buffer, size_t key_buffer_size, size_t *key_buffer_length )
{
	switch (slot_number) {
	case PSA_DRV_SLOT_IOTREFERENCE_RX_DEVICE_PRIVATE_KEY:
		// TODO: partially hardcoded...
		psa_set_key_type(attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
		psa_set_key_bits(attributes, 256);
		psa_set_key_usage_flags(attributes,PSA_KEY_USAGE_SIGN_HASH);
		psa_set_key_algorithm(attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));

		if (key_buffer_size < sizeof(psa_drv_slot_number_t)) {
			return PSA_ERROR_BUFFER_TOO_SMALL;
		}
		*((psa_drv_slot_number_t *) key_buffer) = PSA_DRV_SLOT_IOTREFERENCE_RX_DEVICE_PRIVATE_KEY;
		*key_buffer_length = sizeof(psa_drv_slot_number_t);
		return PSA_SUCCESS;

	default:
		return PSA_ERROR_DOES_NOT_EXIST;
	}
}

psa_status_t psa_driver_iotreference_rx_sign_hash(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg, const uint8_t *hash, size_t hash_length,
    uint8_t *signature, size_t signature_size, size_t *signature_length )
{
	psa_drv_slot_number_t slot_number =  *((psa_drv_slot_number_t *) key_buffer);
	switch (slot_number) {
	case PSA_DRV_SLOT_IOTREFERENCE_RX_DEVICE_PRIVATE_KEY:
		return psa_sign_hash_builtin(attributes, g_key_buffer, g_key_buffer_size, alg, hash, hash_length, signature, signature_size, signature_length);

	default:
		return PSA_ERROR_DOES_NOT_EXIST;
	}
}
