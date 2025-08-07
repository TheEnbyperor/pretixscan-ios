use std::str::FromStr;
use num_traits::cast::ToPrimitive;

#[derive(Debug)]
struct PretixUIC {
    pk_db: uic_ticket::sig::PublicKeyDB
}

#[repr(C)]
#[derive(Debug)]
enum ScanResultType {
    Invalid = 0,
    InvalidTime = 1,
    InvalidProduct = 2,
    InvalidSubEvent = 3,
    Valid = 4,
}

#[repr(C)]
#[derive(Debug)]
struct ScanResult {
    result: ScanResultType,
    unique_id: *const std::os::raw::c_char,
    item_id: i64,
    sub_event_id: i64,
    variation_id: i64,
    _unique_id_box: *mut std::ffi::CString
}

impl ScanResult {
    fn empty(result: ScanResultType) -> ScanResult {
        ScanResult {
            result,
            unique_id: std::ptr::null(),
            item_id: 0,
            sub_event_id: 0,
            variation_id: 0,
            _unique_id_box: std::ptr::null_mut()
        }
    }
}

#[repr(C)]
#[derive(Debug)]
struct Config {
    public_key: *const std::os::raw::c_char,
    security_provider_rics: std::os::raw::c_uint,
    security_provider_ia5: *const std::os::raw::c_char,
    key_id: std::os::raw::c_uint,
    key_id_ia5: *const std::os::raw::c_char,
}

#[repr(C)]
#[derive(Debug)]
struct ScanConfig {
    is_exit: bool,
    event_slug: *const i8,
    checkin_list_all_products: bool,
    checkin_list_limit_products_count: usize,
    checkin_list_limit_products: *const i64,
    checkin_list_has_sub_event_id: bool,
    checkin_list_sub_event_id: i64,
}

#[unsafe(no_mangle)]
extern "C" fn pretix_uic_new(config: *const Config) -> *mut std::os::raw::c_void {
    let config = unsafe { &*config };

    let public_key = unsafe { std::ffi::CStr::from_ptr(config.public_key) };
    let public_key = public_key.to_str().unwrap();
    let security_provider = if config.security_provider_rics != 0 {
        &config.security_provider_rics.to_string()
    } else {
        unsafe { std::ffi::CStr::from_ptr(config.security_provider_ia5) }.to_str().unwrap()
    };
    let key_id = if config.key_id != 0 {
        &config.key_id.to_string()
    } else {
        unsafe { std::ffi::CStr::from_ptr(config.key_id_ia5) }.to_str().unwrap()
    };

    let mut pk_db = uic_ticket::sig::PublicKeyDB::new();
    pk_db.load_key_pem(security_provider, key_id, public_key).unwrap();

    let instance = PretixUIC {
        pk_db,
    };
    
    println!("UIC library configured: {:?}", instance);

    Box::into_raw(Box::new(instance)) as *mut _
}

#[unsafe(no_mangle)]
extern "C" fn pretix_uic_free(i: *mut std::os::raw::c_void) {
    unsafe {
        let _ = Box::from_raw(i as *mut PretixUIC);
    };
}

#[unsafe(no_mangle)]
extern "C" fn pretix_uic_scan(
    i: *mut std::os::raw::c_void, data: *const u8, data_len: std::os::raw::c_int,
    scan_config: *const ScanConfig
) -> *mut ScanResult {
    let instance: &PretixUIC = unsafe { &*(i as *mut PretixUIC) };
    let data = unsafe { std::slice::from_raw_parts(data, data_len as usize) };
    let scan_config = unsafe { &*scan_config };
    println!("UIC scan config: {:?}", scan_config);
    let res = do_scan(instance, data, scan_config);
    println!("UIC scan result: {:?}", res);
    let res = Box::new(res);
    Box::into_raw(res) as *mut _
}

fn do_scan(instance: &PretixUIC, data: &[u8], scan_config: &ScanConfig) -> ScanResult {
    let now = chrono::Utc::now();

    let ticket = match uic_ticket::Ticket::parse(data) {
        Ok(t) => t,
        Err(e) => {
            println!("UIC ticket failed to parse: {:?}", e);
            return ScanResult::empty(ScanResultType::Invalid);
        }
    };

    if let Err(err) = instance.pk_db.verify_ticket(&ticket) {
        println!("UIC ticked signature invalid: {:?}", err);
        return ScanResult::empty(ScanResultType::Invalid);
    }

    let pretix_record = match ticket {
        uic_ticket::Ticket::UicTlbTicket(ticket) => {
            println!("UIC TLB ticket signed by RICS {} with key ID {}", ticket.security_provider_rics, ticket.security_provider_key_id);

            ticket.records.iter().filter_map(|r| if let uic_ticket::tlb_records::Record::PretixTicket(p) = r {
                Some(p)
            } else {
                None
            }).next().cloned()
        },
        uic_ticket::Ticket::UicDosipasTicket(ticket) => {
            println!("UIC Dosipas ticket signed by RICS {} with key ID {}", ticket.security_provider, ticket.key_id);

            if let Some(t) = ticket.end_of_validity {
                if t > now {
                    println!("UIC ticket past end of validity");
                    if !scan_config.is_exit {
                        return ScanResult::empty(ScanResultType::InvalidTime);
                    }
                }
            }

            ticket.records.iter().filter_map(|r| if let uic_ticket::dosipas::Record::PretixTicket(p) = r {
                Some(p)
            } else {
                None
            }).next().cloned()
        },
        _ => {
            println!("Unknown UIC ticket type: {:?}", ticket);
            return ScanResult::empty(ScanResultType::Invalid);
        }
    };

    let pretix_record = match pretix_record {
        Some(pretix_record) => pretix_record,
        None => {
            println!("UIC Pretix record missing");
            return ScanResult::empty(ScanResultType::Invalid);
        }
    };

    println!("UIC Pretix record: {:#?}", pretix_record);

    let event_slug = unsafe { std::ffi::CStr::from_ptr(scan_config.event_slug).to_string_lossy() };
    let item_id = pretix_record.item_id.to_i64().unwrap();
    let sub_event_id = pretix_record.subevent_id.map(|id| id.to_i64().unwrap());
    let variation_id = pretix_record.variation_id.map(|id| id.to_i64().unwrap());

    if event_slug != str::from_utf8(pretix_record.event_slug.as_iso646_bytes()).unwrap() {
        println!("UIC ticket event ID mismatch");
        return ScanResult::empty(ScanResultType::Invalid);
    }

    let valid_from = match (pretix_record.valid_from_year, pretix_record.valid_from_day, pretix_record.valid_from_time) {
        (Some(y), Some(d), Some(t)) => {
            let date = match chrono::NaiveDate::from_yo_opt(y as i32, d as u32) {
                Some(t) => t,
                None => {
                    println!("UIC ticket Valid From out of range");
                    return ScanResult::empty(ScanResultType::Invalid);
                }
            };
            let time = match chrono::NaiveTime::from_num_seconds_from_midnight_opt(t as u32 * 60, 0) {
                Some(t) => t,
                None => {
                    println!("UIC ticket Valid From out of range");
                    return ScanResult::empty(ScanResultType::Invalid);
                }
            };
            Some(date.and_time(time).and_utc())
        },
        (None, None, None) => None,
        _ => {
            println!("UIC ticket Valid From inconsistently set");
            return ScanResult::empty(ScanResultType::Invalid);
        }
    };
    let valid_until = match (pretix_record.valid_until_year, pretix_record.valid_until_day, pretix_record.valid_until_time) {
        (Some(y), Some(d), Some(t)) => {
            let date = match chrono::NaiveDate::from_yo_opt(y as i32, d as u32) {
                Some(t) => t,
                None => {
                    println!("UIC ticket Valid Until out of range");
                    return ScanResult::empty(ScanResultType::Invalid);
                }
            };
            let time = match chrono::NaiveTime::from_num_seconds_from_midnight_opt(t as u32 * 60, 0) {
                Some(t) => t,
                None => {
                    println!("UIC ticket Valid Until out of range");
                    return ScanResult::empty(ScanResultType::Invalid);
                }
            };
            Some(date.and_time(time).and_utc())
        },
        (None, None, None) => None,
        _ => {
            println!("UIC ticket Valid Until inconsistently set");
            return ScanResult::empty(ScanResultType::Invalid);
        }
    };

    if let Some(dt) = valid_from && dt > now && !scan_config.is_exit {
        println!("UIC ticket not yet valid");
        return ScanResult::empty(ScanResultType::InvalidTime);
    }
    if let Some(dt) = valid_until && dt < now && !scan_config.is_exit {
        println!("UIC ticket expired");
        return ScanResult::empty(ScanResultType::InvalidTime);
    }

    if !scan_config.checkin_list_all_products {
        let valid_products = unsafe { std::slice::from_raw_parts(scan_config.checkin_list_limit_products, scan_config.checkin_list_limit_products_count) };
        if !valid_products.contains(&item_id) {
            return ScanResult::empty(ScanResultType::InvalidProduct);
        }
    }

    if scan_config.checkin_list_has_sub_event_id {
        if sub_event_id != Some(scan_config.checkin_list_sub_event_id) {
            return ScanResult::empty(ScanResultType::InvalidSubEvent);
        }
    }

    let unique_id = Box::new(std::ffi::CString::from_str(str::from_utf8(pretix_record.unique_id.as_iso646_bytes()).unwrap()).unwrap());
    ScanResult {
        result: ScanResultType::Valid,
        unique_id: unique_id.as_ptr(),
        item_id,
        sub_event_id: sub_event_id.unwrap_or_default(),
        variation_id: variation_id.unwrap_or_default(),
        _unique_id_box: Box::into_raw(unique_id)
    }
}

#[unsafe(no_mangle)]
extern "C" fn pretix_uic_scan_free(i: *mut std::os::raw::c_void) {
    unsafe {
        let r = Box::from_raw(i as *mut ScanResult);
        if !r._unique_id_box.is_null() {
            let _ = Box::from_raw(r._unique_id_box);
        }
    }
}