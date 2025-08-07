#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef enum {
    PRETIX_UIC_SCAN_INVALID = 0,
    PRETIX_UIC_SCAN_INVALID_TIME = 1,
    PRETIX_UIC_SCAN_INVALID_PRODUCT = 2,
    PRETIX_UIC_SCAN_INVALID_SUB_EVENT = 3,
    PRETIX_UIC_SCAN_VALID = 4
} pretix_uic_scan_result_type;

typedef struct {
    pretix_uic_scan_result_type result;
    const char *unique_id;
    int64_t item_id;
    int64_t subevent_id;
    int64_t variation_id;
} pretix_uic_scan_result;

typedef struct {
    const char  *public_key;
    unsigned int security_provider_rics;
    const char  *security_provider_ia5;
    unsigned int key_id;
    const char  *key_id_ia5;
} pretix_uic_config;

typedef void *pretix_uic;

typedef struct {
    bool           is_exit;
    int8_t const   *event_slug;
    bool           checkin_list_all_products;
    size_t         checkin_list_limit_products_count;
    int64_t const *checkin_list_limit_products;
    bool           checkin_list_has_sub_event_id;
    int64_t        checkin_list_sub_event_id;
} pretix_uic_scan_conf;

pretix_uic pretix_uic_new(const pretix_uic_config *config);
void pretix_uic_free(pretix_uic instance);
pretix_uic_scan_result *pretix_uic_scan(pretix_uic instance, const uint8_t *data, int data_len, const pretix_uic_scan_conf *scan_conf);
void pretix_uic_scan_free(pretix_uic_scan_result *instance);

