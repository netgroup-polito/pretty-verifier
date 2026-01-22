use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use libc::size_t;


#[repr(C)]
struct PrettyVerifierOptsC {
    source_paths: *const c_char,
    bytecode_path: *const c_char,
    enumerate: c_int,
}

const PV_ERR_GENERIC: c_int = -1;
const PV_ERR_TRUNCATED: c_int = -2;
const PV_ERR_NOT_FOUND: c_int = -3;
const PV_ERR_NO_ACCESS: c_int = -4;

#[link(name = "pretty-verifier")]
unsafe extern "C" {
    fn pretty_verifier(
        log: *const c_char,
        opts: *const PrettyVerifierOptsC,
        out_buf: *mut c_char,
        out_size: size_t,
    ) -> c_int;
}


#[derive(Debug)]
pub struct Options<'a> {
    pub source_paths: &'a str,
    pub bytecode_path: &'a str,
    pub enumerate: bool
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Pretty verifier failed with a generic error (code {0})")]
    Generic(i32),

    #[error("Output truncated (buffer size: {0} bytes). Partial output: {1}")]
    Truncated(usize, String),

    #[error("The 'pretty-verifier' command was not found in PATH")]
    NotFound,

    #[error("Permission denied when executing 'pretty-verifier'")]
    PermissionDenied,

    #[error("Unknown error code returned: {0}")]
    Unknown(i32),

    #[error("Invalid UTF-8 sequence")]
    Utf8Error(#[from] std::str::Utf8Error),

    #[error("CString conversion error")]
    NulError(#[from] std::ffi::NulError)
}


pub fn format(raw_log: &str, opts: Options) -> Result<String, Error> {
    let c_log = CString::new(raw_log)?;
    let c_source = CString::new(opts.source_paths)?;
    let c_bytecode = CString::new(opts.bytecode_path)?;

    let c_opts = PrettyVerifierOptsC {
        source_paths: c_source.as_ptr(),
        bytecode_path: c_bytecode.as_ptr(),
        enumerate: if opts.enumerate { 1 } else { 0 },
    };
    let buf_size =  raw_log.len() + 4096;

    let mut out_buf: Vec<u8> = vec![0u8; buf_size]; 

    let res = unsafe {
        pretty_verifier(
            c_log.as_ptr(),
            &c_opts,
            out_buf.as_mut_ptr() as *mut c_char,
            out_buf.len() as size_t,
        )
    };

    if res >=0 {
        let c_out = unsafe { CStr::from_ptr(out_buf.as_ptr() as *const c_char) };
        return Ok(c_out.to_str()?.to_owned());
    }

    match res {
        PV_ERR_TRUNCATED => {
            let c_out = unsafe { CStr::from_ptr(out_buf.as_ptr() as *const c_char) };
            let partial = c_out.to_string_lossy().into_owned();
            Err(Error::Truncated(buf_size, partial))
        },
        PV_ERR_GENERIC => Err(Error::Generic(res as i32)),
        PV_ERR_NOT_FOUND => Err(Error::NotFound),
        PV_ERR_NO_ACCESS => Err(Error::PermissionDenied),
        _ => Err(Error::Unknown(res as i32)),
    }
}