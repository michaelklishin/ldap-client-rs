// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn compile_fail() {
    trybuild::TestCases::new().compile_fail("tests/compile_fail/*.rs");
}
