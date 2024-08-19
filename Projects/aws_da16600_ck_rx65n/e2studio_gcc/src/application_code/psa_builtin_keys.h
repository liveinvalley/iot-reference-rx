#ifndef PSA_BUILTIN_KEYS_H_
#define PSA_BUILTIN_KEYS_H_

#include <psa/crypto.h>

#define PSA_KEY_ID_BUILTIN_IOTREFERENCE_RX_DEVICE_PRIVATE_KEY MBEDTLS_PSA_KEY_ID_BUILTIN_MIN

#define PSA_KEY_LOCATION_IOTREFERENCE_RX 0xf0
#define PSA_KEY_LIFETIME_IOTREFERENCE_RX PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(PSA_KEY_PERSISTENCE_READ_ONLY, PSA_KEY_LOCATION_IOTREFERENCE_RX)

#define PSA_DRV_SLOT_IOTREFERENCE_RX_DEVICE_PRIVATE_KEY 0

psa_status_t mbedtls_psa_platform_get_builtin_key(
     mbedtls_svc_key_id_t key_id,
     psa_key_lifetime_t *lifetime,
     psa_drv_slot_number_t *slot_number);

psa_status_t psa_driver_iotreference_rx__get_key_buffer_size(
    const psa_key_attributes_t *attributes,
    size_t *key_buffer_size );

psa_status_t psa_driver_iotreference_rx_get_builtin_key(
    psa_drv_slot_number_t slot_number,
    psa_key_attributes_t *attributes,
    uint8_t *key_buffer, size_t key_buffer_size, size_t *key_buffer_length );

psa_status_t psa_driver_iotreference_rx_sign_hash(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg, const uint8_t *hash, size_t hash_length,
    uint8_t *signature, size_t signature_size, size_t *signature_length );

psa_status_t psa_driver_iotreference_rx_generate_key(
    const psa_key_attributes_t *attributes,
    uint8_t *key_buffer, size_t key_buffer_size, size_t *key_buffer_length );

#endif /* PSA_BUILTIN_KEYS_H_ */
