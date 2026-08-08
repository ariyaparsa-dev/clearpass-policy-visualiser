SELECT
    id,
    mac AS mac_address,
    ip AS ip_address,
    hostname,
    mac_vendor,
    device_category,
    device_family,
    device_name,
    other_category,
    other_family,
    other_name,
    fingerprint,
    extras,
    updated_at,
    added_at,
    profiled_by
FROM tips_endpoint_profiles
WHERE mac IS NOT NULL
ORDER BY updated_at DESC;