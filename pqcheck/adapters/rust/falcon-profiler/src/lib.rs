//! No-op `profiling` attribute: expands to the annotated item
//! unchanged. Upstream falcon-rust uses this attribute purely for
//! optional instrumentation; dropping the instrumentation does not
//! alter the codec's inputs, outputs, or control flow.
extern crate proc_macro;

use proc_macro::TokenStream;

#[proc_macro_attribute]
pub fn profiling(_args: TokenStream, item: TokenStream) -> TokenStream {
    item
}
