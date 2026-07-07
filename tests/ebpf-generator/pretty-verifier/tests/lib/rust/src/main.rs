use libbpf_rs::ObjectBuilder;
use libbpf_rs::{PrintLevel, set_print};
use pretty_verifier::{self, Options};
use std::sync::Mutex;

static GLOBAL_LOG_BUFFER: Mutex<String> = Mutex::new(String::new());

fn logger_callback(_level: PrintLevel, msg: String) {
    if let Ok(mut guard) = GLOBAL_LOG_BUFFER.lock() {
        guard.push_str(&msg);
    }
}

fn main() -> anyhow::Result<()> {
    // Redirect the stderr of libbpf-rs to a global variable
    set_print(Some((
        PrintLevel::Debug,
        logger_callback
    )));

    let filename = "test.bpf.o";
    let source_filename = "test.bpf.c";

    let open_object = ObjectBuilder::default().open_file(filename)?;

    // Load the eBPF program
    match open_object.load() {
        Ok(_) => {
            println!("Program loaded successfully.");
        }
        Err(_err) => {
            // Retrieve the eBPF verifier log from the global variable
            let captured_log = GLOBAL_LOG_BUFFER.lock().unwrap().clone();

            // Set thre Pretty Verifier options
            let pv_opts = Options {
                source_paths: source_filename,
                bytecode_path: filename,
                enumerate: false
            };
            // Pass the raw verifier log to Pretty Verifier
            match pretty_verifier::format(&captured_log, pv_opts) {
                Ok(formatted_output) => {
                    // Print the formatted output
                    println!("{}", formatted_output);
                },
                // Manage possible errors
                Err(pretty_verifier::Error::Truncated(_, partial)) => {
                    println!("Output truncated:\n{}", partial);
                },
                Err(pretty_verifier::Error::NotFound) => {
                    eprintln!("Error: 'pretty-verifier' tool not found in PATH.");
                },
                Err(e) => {
                    eprintln!("Error formatting log: {}", e);
                }
            }
        }
    }

    Ok(())
}