fn main() {
    capnpc::CompilerCommand::new()
        .src_prefix("src/schema")
        .file("src/schema/tunnelrpc.capnp")
        .file("src/schema/quic_metadata_protocol.capnp")
        .run()
        .expect("failed to compile capnp schemas");
}
