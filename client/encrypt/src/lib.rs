use threshold_crypto::{PublicKey};
use std::os::raw::c_char;
use std::ffi::{CString, CStr};

#[no_mangle]
pub extern "C" fn encrypt(public_key: *const c_char, message: *const c_char) -> *mut c_char {
    let public : &str;
    let m: &str;
    unsafe {
        public = CStr::from_ptr(public_key).to_str().unwrap();
        m = CStr::from_ptr(message).to_str().unwrap();
    }
    let public_key: PublicKey = serde_json::from_str(&public).unwrap();
    let cipher = public_key.encrypt(m);
    let c = serde_json::to_string(&cipher).unwrap();
    let c = CString::new(c).unwrap();
    c.into_raw()
}
