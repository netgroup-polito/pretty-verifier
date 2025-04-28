# Test Suite

This folder contains the testing utilities developed alongside **Pretty Verifier** to evaluate its effectiveness.

## Running Tests

Move to the test folder:
```bash
cd test_cases/
```
Compile the source files:
```bash
make
```
Move back to the test folder:
```bash
cd ..
```
To run all tests, execute:
```bash
python3 test.py
```

This will automatically run the available test cases and check the Pretty Verifier behavior.

### Structure

- **`test_cases/`**: Contains all test cases.  
  Each test case is named based on the error it tests, with an additional suffix to distinguish sub-cases.

- **`load.sh`**:  
  Allows you to manually load a test file for direct testing. To use it, provide the file name without the extension.

- **`Makefile`**:  
  Generates the corresponding `.o` object files for each test case.  
  Use the following commands:

    - `make`: To compile the object files.
    - `make clean`: To remove the `vmlinux` file and the other generated `.o` object files.

