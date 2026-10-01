use ldap_client::tls_config::TlsConfig;

fn main() {
    let _ = TlsConfig {
        ..TlsConfig::default()
    };
}
